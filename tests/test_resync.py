"""`ai-safe resync`: rebuild the workspace in place after staging verification."""

import errno
import hashlib
import json
import os

import pytest
from typer.testing import CliRunner

from ai_safe import resync as resync_mod
from ai_safe.cli import app
from ai_safe.integration import integrate
from ai_safe.resync import pending_changes, resync
from ai_safe.security import MARKER_FILE, SecurityError
from ai_safe.models import Issue, Severity
from ai_safe.verifier import VerificationReport
from ai_safe.workspace import Session, replace_tree_contents
from conftest import prepare, tree_snapshot, write

APPROVE = lambda rr, patch: True  # noqa: E731


@pytest.fixture
def project(make_repo, fake):
    key, pw = fake.openai(), fake.password()
    repo = make_repo({
        ".gitignore": ".env\n",
        "app/settings.py": f'import os\n\nAPI_KEY = "{key}"\nDB_PASSWORD = "{pw}"\nDEBUG = False\n\n\ndef hello():\n    return "hi"\n',
        "app/util.py": "def add(a, b):\n    return a + b\n",
        "README.md": "# demo\n",
    })
    write(repo, {".env": f"DB_PASSWORD={pw}\n"})
    p = prepare(repo)
    assert p.verification.passed
    p.key, p.pw = key, pw
    return p


def run(p, *, discard=False):
    return resync(p.session, p.cfg, p.store, p.scanner, p.salt, discard=discard, passphrase=None)


def edit_ws(p, rel="app/util.py", text="def add(a, b):\n    return b + a\n"):
    (p.ws / rel).write_text(text)


def session_json_hash(p) -> str:
    return hashlib.sha256((p.session.state_path / "session.json").read_bytes()).hexdigest()


def leftovers(p) -> tuple[list, list]:
    staging_state = [d.name for d in p.store.sessions_dir.iterdir() if d.name != p.session.id]
    extra_ws = [d.name for d in p.ws.parent.iterdir() if d != p.ws]
    return staging_state, extra_ws


def builtin_cfg_file(p):
    cfg = p.repo.parent / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    return cfg


# ---------------------------------------------------------------------------
# library
# ---------------------------------------------------------------------------


def test_resync_clean_workspace_picks_up_original_changes(project):
    ino = os.stat(project.ws).st_ino
    path = project.ws
    marker = (project.ws / MARKER_FILE).read_bytes()
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return a + b + 0\n")
    res = run(project)
    assert res.ok, res.reason
    assert project.session.workspace_path == path
    assert os.stat(project.ws).st_ino == ino
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return a + b + 0\n"
    assert (project.ws / MARKER_FILE).read_bytes() == marker
    loaded = Session.load(project.session.state_path)
    assert loaded.status == "verified" and loaded.verified_tree_hash and loaded.integrated_tree_hash is None
    # snapshot and manifest were rebuilt: the new content is not a pending change
    assert pending_changes(loaded) == []
    assert (loaded.snapshot_dir / "app/util.py").read_text().endswith("+ 0\n")
    assert leftovers(project) == ([], [])


def test_resync_keeps_placeholders_and_redacts_new_secret(project, fake):
    before = (project.ws / "app/settings.py").read_text()
    token = fake.github()
    write(project.repo, {"app/client.py": f'GITHUB_TOKEN = "{token}"\n'})
    res = run(project)
    assert res.ok, res.reason
    assert (project.ws / "app/settings.py").read_text() == before
    client = (project.ws / "app/client.py").read_text()
    assert token not in client and "${AI_SAFE_SECRET_" in client
    for p in project.ws.rglob("*"):
        if p.is_file() and not p.is_symlink():
            data = p.read_bytes()
            assert token.encode() not in data and project.key.encode() not in data


def test_resync_refuses_with_pending_changes(project):
    edit_ws(project)
    snap = tree_snapshot(project.ws)
    res = run(project)
    assert not res.ok and "resync --discard" in res.reason
    assert tree_snapshot(project.ws) == snap


def test_resync_discard_throws_away_changes(project):
    original = tree_snapshot(project.ws)
    edit_ws(project)
    write(project.ws, {"app/new.py": "X = 1\n"})
    res = run(project, discard=True)
    assert res.ok, res.reason
    assert tree_snapshot(project.ws) == original


def test_resync_allowed_after_full_integration(project):
    edit_ws(project)
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert not res.aborted, res.reason
    assert pending_changes(project.session) == []
    out = run(project)
    assert out.ok, out.reason
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return b + a\n"
    # a second integration in the same session works again (snapshot rebuilt)
    edit_ws(project, text="def add(a, b):\n    return (b + a)\n")
    again = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert not again.aborted, again.reason


def test_resync_after_partial_integration_requires_discard(project):
    edit_ws(project)
    write(project.ws, {"app/x.py": "X = 1\n"})
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE,
                    exclude_paths=("app/x.py",), cwd=project.repo)
    assert not res.aborted, res.reason
    out = run(project)
    assert not out.ok and "resync --discard" in out.reason


def test_resync_after_integration_then_more_edits_requires_discard(project):
    edit_ws(project)
    integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    write(project.ws, {"app/later.py": "Y = 2\n"})
    assert not run(project).ok


def test_resync_verification_failure_leaves_workspace_untouched(project, monkeypatch):
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return 42\n")
    snap = tree_snapshot(project.ws)
    sj = session_json_hash(project)
    manifest = project.session.manifest_path.read_bytes()

    def failing(ws, *a, **kw):
        return VerificationReport(str(ws), issues=[Issue(Severity.ERROR, "test-fail", "x", "synthetic failure")])

    monkeypatch.setattr(resync_mod, "verify_workspace", failing)
    res = run(project)
    assert not res.ok and res.reason == "verification failed" and res.verification is not None
    assert tree_snapshot(project.ws) == snap
    assert session_json_hash(project) == sj
    assert project.session.manifest_path.read_bytes() == manifest
    assert leftovers(project) == ([], [])


def test_resync_sanitizer_error_leaves_workspace_untouched(project, monkeypatch):
    snap = tree_snapshot(project.ws)
    sj = session_json_hash(project)

    def boom(self, *a, **kw):
        raise SecurityError("synthetic sanitizer failure")

    monkeypatch.setattr(resync_mod.Sanitizer, "run", boom)
    with pytest.raises(SecurityError):
        run(project)
    assert tree_snapshot(project.ws) == snap
    assert session_json_hash(project) == sj
    assert leftovers(project) == ([], [])


def test_resync_swap_failure_rolls_back_workspace_and_state(project, monkeypatch):
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return 7\n")
    snap = tree_snapshot(project.ws)
    state_snap = tree_snapshot(project.session.state_path)
    real_rename = os.rename
    calls = {"n": 0}

    def flaky(src, dst):
        # fail half-way through moving the staged workspace into the live one
        if "ai-safe-ws-" in str(src) and str(dst).startswith(str(project.ws) + os.sep):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(errno.EXDEV, "synthetic cross-device")
        return real_rename(src, dst)

    monkeypatch.setattr(os, "rename", flaky)
    with pytest.raises(SecurityError):
        run(project)
    monkeypatch.setattr(os, "rename", real_rename)
    assert tree_snapshot(project.ws) == snap
    assert tree_snapshot(project.session.state_path) == state_snap
    assert leftovers(project) == ([], [])


def test_resync_refuses_inside_agent(project, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    with pytest.raises(SecurityError):
        run(project)


def test_resync_refuses_workspace_with_foreign_marker(project):
    (project.ws / MARKER_FILE).write_text(json.dumps({"session_id": "0" * 16}))
    with pytest.raises(SecurityError):
        run(project)


def test_replace_tree_contents_keeps_dir_and_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    dst, src = tmp_path / "dst", tmp_path / "src"
    dst.mkdir()
    src.mkdir()
    (dst / "old.txt").write_text("old")
    (dst / "sub").mkdir()
    (dst / "sub" / "f").write_text("f")
    os.symlink(outside, dst / "link")
    (src / "new.txt").write_text("new")
    (src / "d").mkdir()
    (src / "d" / "g").write_text("g")
    ino = os.stat(dst).st_ino
    replace_tree_contents(dst, src)
    assert os.stat(dst).st_ino == ino
    assert sorted(p.name for p in dst.iterdir()) == ["d", "new.txt"]
    assert (dst / "d" / "g").read_text() == "g"
    assert (outside / "keep.txt").read_text() == "keep"
    assert list(src.iterdir()) == []


def test_replace_tree_contents_exdev_is_security_error(tmp_path, monkeypatch):
    dst, src = tmp_path / "dst", tmp_path / "src"
    dst.mkdir()
    src.mkdir()
    (dst / "old.txt").write_text("old")
    (src / "new.txt").write_text("new")

    def exdev(a, b):
        raise OSError(errno.EXDEV, "synthetic cross-device")

    monkeypatch.setattr(os, "rename", exdev)
    with pytest.raises(SecurityError):
        replace_tree_contents(dst, src)
    assert (dst / "old.txt").read_text() == "old"


def test_session_list_skips_non_session_dirs(project):
    staging = project.store.sessions_dir / f"{project.session.id}.resync"
    staging.mkdir()
    (staging / "session.json").write_text((project.session.state_path / "session.json").read_text())
    ids = [s.state_dir for s in project.store.list()]
    assert ids == [str(project.session.state_path)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_resync_discard_requires_typed_word(project, monkeypatch):
    cfg = builtin_cfg_file(project)
    edit_ws(project)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["resync", "-s", project.session.id, "-c", str(cfg), "--discard"], input="no\n")
    assert r.exit_code == 1, r.output
    assert "Close any AI session" in r.output
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return b + a\n"
    ok = CliRunner().invoke(app, ["resync", "-s", project.session.id, "-c", str(cfg), "--discard"], input="discard\n")
    assert ok.exit_code == 0, ok.output
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return a + b\n"


def test_cli_resync_pending_without_discard_exits_1(project, monkeypatch):
    cfg = builtin_cfg_file(project)
    edit_ws(project)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["resync", "-s", project.session.id, "-c", str(cfg)])
    assert r.exit_code == 1 and "resync --discard" in r.output


def test_resync_output_has_no_secrets(project, monkeypatch):
    cfg = builtin_cfg_file(project)
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return a + b + 1\n")
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["resync", "-s", project.session.id, "-c", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "Workspace resynced (same path)" in r.output and str(project.ws) in r.output
    assert project.key not in r.output and project.pw not in r.output


def test_resync_aborts_if_ai_edits_during_staging(project, monkeypatch):
    real_run = resync_mod.Sanitizer.run

    def run_while_ai_edits(self, *a, **kw):
        out = real_run(self, *a, **kw)
        (project.ws / "app/late.py").write_text("LATE = 1\n")  # AI keeps working
        return out

    monkeypatch.setattr(resync_mod.Sanitizer, "run", run_while_ai_edits)
    res = run(project)
    assert not res.ok and "resync --discard" in res.reason
    assert (project.ws / "app/late.py").read_text() == "LATE = 1\n"
    assert leftovers(project) == ([], [])


# ---------------------------------------------------------------------------
# failure during the swap: never leave a "verified" session over a mixed workspace
# ---------------------------------------------------------------------------


def test_replace_tree_contents_keyboard_interrupt_rolls_back(tmp_path, monkeypatch):
    dst, src = tmp_path / "dst", tmp_path / "src"
    dst.mkdir()
    src.mkdir()
    for n in ("a.txt", "b.txt"):
        (dst / n).write_text("old " + n)
    for n in ("c.txt", "d.txt", "e.txt"):
        (src / n).write_text("new " + n)
    real_rename = os.rename
    calls = {"n": 0}

    def interrupted(a, b):
        if str(a).startswith(str(src) + os.sep):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
        return real_rename(a, b)

    monkeypatch.setattr(os, "rename", interrupted)
    with pytest.raises(KeyboardInterrupt):
        replace_tree_contents(dst, src)
    monkeypatch.setattr(os, "rename", real_rename)
    assert sorted(p.name for p in dst.iterdir()) == ["a.txt", "b.txt"]
    assert sorted(p.name for p in src.iterdir()) == ["c.txt", "d.txt", "e.txt"]
    assert [p.name for p in tmp_path.iterdir() if p.name not in ("dst", "src")] == []


def _open_cli(p):
    return CliRunner().invoke(app, ["open", "-s", p.session.id])


def test_resync_crash_mid_swap_leaves_session_resyncing(project, monkeypatch):
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return 9\n")
    before = Session.load(project.session.state_path)
    seen = {}

    def dies(dst, src):
        # what is on disk at this point is what a SIGKILL would leave behind
        seen["session"] = Session.load(project.session.state_path)
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(resync_mod, "replace_tree_contents", dies)
    with pytest.raises(RuntimeError):
        run(project)
    crashed = seen["session"]
    assert crashed.status == "resyncing" and crashed.verified_tree_hash is None
    # complete rollback: the old status and hash are restored
    after = Session.load(project.session.state_path)
    assert (after.status, after.verified_tree_hash) == (before.status, before.verified_tree_hash)
    assert leftovers(project) == ([], [])

    # now pretend the process had died: the on-disk session is the in-flight one
    crashed.save()
    monkeypatch.chdir(project.repo)
    r = _open_cli(project)
    assert r.exit_code == 1, r.output
    crashed.verified_tree_hash = before.verified_tree_hash  # even with a hash, "resyncing" refuses
    crashed.save()
    assert _open_cli(project).exit_code == 1
    edit_ws(project)
    with pytest.raises(SecurityError, match="resync"):
        integrate(crashed, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)


def test_open_refuses_failed_session(project, monkeypatch):
    project.session.status = "failed"
    project.session.save()
    monkeypatch.chdir(project.repo)
    assert _open_cli(project).exit_code == 1


def test_resync_incomplete_workspace_rollback_stays_resyncing(project, monkeypatch):
    from ai_safe.workspace import IncompleteRollbackError

    def half(dst, src):
        raise IncompleteRollbackError("synthetic: old contents kept in /x")

    monkeypatch.setattr(resync_mod, "replace_tree_contents", half)
    manifest = project.session.manifest_path.read_bytes()
    with pytest.raises(SecurityError):
        run(project)
    after = Session.load(project.session.state_path)
    assert after.status == "resyncing" and after.verified_tree_hash is None
    assert project.session.manifest_path.read_bytes() == manifest  # old state is back


def test_resync_state_undo_failure_keeps_old_state(project, monkeypatch):
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return 5\n")
    manifest = project.session.manifest_path.read_bytes()
    real_rename = os.rename

    def ws_fails(dst, src):
        # workspace swap fails and the state undo fails too (double fault)
        def no_restore(a, b):
            if f"{os.sep}.old{os.sep}" in str(a):
                raise OSError(errno.EIO, "synthetic I/O error")
            return real_rename(a, b)
        monkeypatch.setattr(os, "rename", no_restore)
        raise SecurityError("workspace replacement failed (synthetic); workspace left untouched")

    monkeypatch.setattr(resync_mod, "replace_tree_contents", ws_fails)
    with pytest.raises(SecurityError, match=r"\.resync") as exc:
        run(project)
    monkeypatch.setattr(os, "rename", real_rename)
    old = project.store.sessions_dir / f"{project.session.id}.resync" / ".old"
    assert str(old) in str(exc.value)
    assert (old / "manifest.json").read_bytes() == manifest
    assert (old / "snapshot").is_dir()
    after = Session.load(project.session.state_path)
    assert after.status == "resyncing" and after.verified_tree_hash is None
    # a later resync never shreds the kept state
    with pytest.raises(SecurityError, match=r"\.old"):
        run(project, discard=True)
    assert (old / "manifest.json").read_bytes() == manifest


def test_swap_state_undo_failure_keeps_old_state(tmp_path, monkeypatch):
    live, stage = tmp_path / "live", tmp_path / "stage"
    live.mkdir()
    stage.mkdir()
    for n in resync_mod.STATE_ITEMS:
        (live / n).write_text("old")
        (stage / n).write_text("new")
    real_rename = os.rename
    n_calls = {"n": 0}

    def flaky(a, b):
        n_calls["n"] += 1
        if n_calls["n"] == 4 or f"{os.sep}.old{os.sep}" in str(a):
            raise OSError(errno.EIO, "synthetic I/O error")
        return real_rename(a, b)

    monkeypatch.setattr(os, "rename", flaky)
    with pytest.raises(SecurityError, match=r"\.old"):
        resync_mod._swap_state(live, stage)
    monkeypatch.setattr(os, "rename", real_rename)
    assert (stage / ".old" / "manifest.json").read_text() == "old"


def test_cli_verify_does_not_clear_resyncing(project, monkeypatch):
    cfg = builtin_cfg_file(project)
    project.session.status, project.session.verified_tree_hash = "resyncing", None
    project.session.save()
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["verify", "-s", project.session.id, "-c", str(cfg)])
    after = Session.load(project.session.state_path)
    assert after.status == "resyncing" and after.verified_tree_hash is None, r.output
    assert r.exit_code == 1 and "ai-safe resync" in r.output
