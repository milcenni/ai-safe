import os
import subprocess

import pytest
from typer.testing import CliRunner

from ai_safe.cli import app
from ai_safe.integration import _validate_targets, integrate
from ai_safe.review import PlannedChange, review_session
from ai_safe.security import SecurityError
from conftest import builtin_config, git, prepare, write

APPROVE = lambda rr, patch: True  # noqa: E731
DECLINE = lambda rr, patch: False  # noqa: E731


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


def review(p):
    return review_session(p.session, p.cfg, p.scanner)


def blocking_codes(rr):
    return {i.code for i in rr.issues if i.severity.blocking}


def edit(p, rel, old, new):
    f = p.ws / rel
    f.write_text(f.read_text().replace(old, new))


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


def test_review_clean_changes_pass(project):
    edit(project, "app/util.py", "return a + b", "return a + b  # sum")
    write(project.ws, {"app/new_module.py": "VALUE = 1\n"})
    rr = review(project)
    assert rr.passed, rr.public()
    assert {p.path for p in rr.plan} == {"app/util.py", "app/new_module.py"}


def test_secret_introduced_by_ai_is_blocked(project, fake):
    write(project.ws, {"app/client.py": f'GITHUB_TOKEN = "{fake.github()}"\n'})
    rr = review(project)
    assert "hardcoded-credential" in blocking_codes(rr) and not rr.plan


def test_placeholder_incorrectly_replaced(project):
    edit(project, "app/settings.py", '"${AI_SAFE_SECRET_API_KEY}"', '"replaced-by-ai-value"')
    rr = review(project)
    assert "placeholder-replaced" in blocking_codes(rr)


def test_placeholder_copied_into_new_code(project):
    write(project.ws, {"app/other.py": 'TOKEN = "${AI_SAFE_SECRET_API_KEY}"\n'})
    assert "placeholder-in-new-code" in blocking_codes(review(project))


def test_unknown_placeholder(project):
    write(project.ws, {"app/other.py": 'X = "${AI_SAFE_SECRET_MADE_UP}"\n'})
    assert "unknown-placeholder" in blocking_codes(review(project))


def test_ai_attempting_to_modify_env(project):
    write(project.ws, {".env": "DB_PASSWORD=from-ai\n"})
    rr = review(project)
    assert "sensitive-file" in blocking_codes(rr)


def test_symlink_created_by_ai(project, tmp_path):
    os.symlink(project.repo / ".git", project.ws / "orig-git")  # attempt to reach original history
    rr = review(project)
    assert "symlink" in blocking_codes(rr)


def test_security_config_and_marker_tampering(project):
    write(project.ws, {"ai-safe.yaml": "version: 1\n", ".gitleaksignore": "x\n"})
    (project.ws / ".ai-safe-workspace.json").write_text("{}")
    codes = blocking_codes(review(project))
    assert {"security-config", "marker-tampered"} <= codes


def test_nested_git_and_claude_metadata_not_integrated(project):
    subprocess.run(["git", "init", "-q"], cwd=project.ws, check=True)
    write(project.ws, {".claude/settings.local.json": "{}\n"})
    edit(project, "app/util.py", "return a + b", "return b + a")
    rr = review(project)
    assert rr.passed
    assert [p.path for p in rr.plan] == ["app/util.py"]
    assert any(".claude/settings.local.json" in s for s in rr.skipped)


def test_unexpected_binary_and_sensitive_config(project):
    (project.ws / "payload.bin").write_bytes(b"\x00\x01\x02")
    write(project.ws, {".github/workflows/ci.yml": "on: push\n"})
    rr = review(project)
    assert "unexpected-binary" in blocking_codes(rr)
    assert any(i.code == "sensitive-config" for i in rr.issues)


def test_conflict_when_ai_edits_credential_line_keeping_placeholder(project):
    edit(project, "app/settings.py", 'API_KEY = "${AI_SAFE_SECRET_API_KEY}"', 'API_KEY = "${AI_SAFE_SECRET_API_KEY}"  # main key')
    rr = review(project)
    assert "conflict" in blocking_codes(rr) or "placeholder-in-new-code" in blocking_codes(rr)


# ---------------------------------------------------------------------------
# integration
# ---------------------------------------------------------------------------


def test_integration_preserves_original_credentials(project):
    edit(project, "app/settings.py", 'return "hi"', 'return "hello"')
    edit(project, "app/util.py", "return a + b", "return a + b + 0")
    head = git(project.repo, "rev-parse", "HEAD")
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert not res.aborted, (res.reason, res.review and res.review.public(), res.issues)
    s = (project.repo / "app/settings.py").read_text()
    assert f'API_KEY = "{project.key}"' in s and f'DB_PASSWORD = "{project.pw}"' in s
    assert 'return "hello"' in s and "AI_SAFE_SECRET" not in s
    assert (project.repo / ".env").read_text() == f"DB_PASSWORD={project.pw}\n"
    # no commit, no staging
    assert git(project.repo, "rev-parse", "HEAD") == head
    assert git(project.repo, "diff", "--cached", "--name-only") == ""
    # patch record is redacted
    patch = open(res.patch_path).read()
    assert project.key not in patch and project.pw not in patch


def test_removing_hardcoded_credential_is_applied_with_warning(project):
    edit(project, "app/settings.py", 'API_KEY = "${AI_SAFE_SECRET_API_KEY}"', 'API_KEY = os.environ["API_KEY"]')
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert not res.aborted, res.reason
    s = (project.repo / "app/settings.py").read_text()
    assert 'API_KEY = os.environ["API_KEY"]' in s and project.key not in s
    assert f'DB_PASSWORD = "{project.pw}"' in s
    assert any(i.code == "credential-removed" for i in res.review.issues)


def test_declined_approval_writes_nothing(project):
    edit(project, "app/util.py", "return a + b", "return 42")
    before = (project.repo / "app/util.py").read_text()
    res = integrate(project.session, project.cfg, project.scanner, confirm=DECLINE, cwd=project.repo)
    assert res.aborted and res.reason == "not approved by developer"
    assert (project.repo / "app/util.py").read_text() == before


def test_blocking_review_prevents_integration(project, fake):
    edit(project, "app/util.py", "return a + b", "return a - b")
    write(project.ws, {"app/leak.py": f'SLACK = "xoxb-{fake.password()}{fake.password()}"\n'})
    before = (project.repo / "app/util.py").read_text()
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert res.aborted and (project.repo / "app/util.py").read_text() == before
    assert not (project.repo / "app/leak.py").exists()


def test_original_changed_since_sanitize_aborts(project):
    edit(project, "app/util.py", "return a + b", "return a * b")
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return b + a\n")
    rr = review(project)
    assert "original-changed" in blocking_codes(rr)


def test_new_file_cannot_overwrite_unshared_original(project):
    # README exists in original; simulate AI creating a file at an ignored path
    (project.repo / "local.cfg").write_text("mine\n")  # untracked, created after sanitize
    write(project.ws, {"local.cfg": "from ai\n"})
    assert "would-overwrite" in blocking_codes(review(project))


def test_deletion(project):
    (project.ws / "README.md").unlink()
    res = integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)
    assert not res.aborted and res.deleted == ["README.md"] and not (project.repo / "README.md").exists()


def test_path_traversal_and_symlink_targets_rejected(project, tmp_path):
    for bad in ("../outside.py", "/etc/passwd", "a/../../x.py", ".git/config", ".env", "app\\..\\x"):
        with pytest.raises(SecurityError):
            _validate_targets([PlannedChange(bad, "write", b"x", 0o644, True)], project.repo, project.cfg)
    # symlinked directory inside the original repo must not be written through
    os.symlink(tmp_path, project.repo / "linked")
    with pytest.raises(SecurityError):
        _validate_targets([PlannedChange("linked/evil.py", "write", b"x", 0o644, True)], project.repo, project.cfg)
    assert not (tmp_path / "evil.py").exists()


def test_integrate_refuses_inside_ai_agent(project, monkeypatch):
    edit(project, "app/util.py", "return a + b", "return 1")
    monkeypatch.setenv("CLAUDECODE", "1")
    with pytest.raises(SecurityError, match="AI agent"):
        integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)


def test_integrate_refuses_from_workspace(project):
    with pytest.raises(SecurityError, match="inside the AI workspace"):
        integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.ws)


def test_cli_review_and_integrate_end_to_end(project, monkeypatch):
    cfg = project.repo.parent / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    edit(project, "app/util.py", "return a + b", "return a + b  # reviewed")
    monkeypatch.chdir(project.ws)
    r = CliRunner().invoke(app, ["review", "-c", str(cfg)])
    assert r.exit_code == 0, r.output
    monkeypatch.chdir(project.repo)
    declined = CliRunner().invoke(app, ["integrate", "-c", str(cfg)], input="no\n")
    assert declined.exit_code == 1 and "not approved" in declined.output
    ok = CliRunner().invoke(app, ["integrate", "-c", str(cfg)], input="apply\n")
    assert ok.exit_code == 0, ok.output
    assert "# reviewed" in (project.repo / "app/util.py").read_text()
    assert project.key not in ok.output and project.pw not in ok.output
    assert "Nothing was committed" in ok.output


def test_integrate_refuses_unverified_workspace(project):
    edit(project, "app/util.py", "return a + b", "return 1")
    project.session.verified_tree_hash = None
    project.session.save()
    with pytest.raises(SecurityError, match="never passed"):
        integrate(project.session, project.cfg, project.scanner, confirm=APPROVE, cwd=project.repo)


def test_hard_link_rejected(project, tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("data\n")
    os.link(outside, project.ws / "app" / "linked.txt")
    rr = review(project)
    assert "hard-link" in blocking_codes(rr)


@pytest.mark.gitleaks
def test_full_flow_with_gitleaks_engine(make_repo, fake, gitleaks_bin):
    from ai_safe.config import AISafeConfig

    key = fake.openai()
    repo = make_repo({"app.py": f'API_KEY = "{key}"\n\n\ndef f():\n    return 1\n'})
    p = prepare(repo, AISafeConfig())
    assert p.verification.passed and "gitleaks" in p.verification.engines
    edit(p, "app.py", "return 1", "return 2")
    write(p.ws, {"leak.py": f'T = "{fake.github()}"\n'})
    rr = review(p)
    assert {"hardcoded-credential", "gitleaks"} & blocking_codes(rr)
    (p.ws / "leak.py").unlink()
    res = integrate(p.session, p.cfg, p.scanner, confirm=APPROVE, cwd=p.repo)
    assert not res.aborted, (res.reason, res.issues)
    assert f'API_KEY = "{key}"' in (repo / "app.py").read_text() and "return 2" in (repo / "app.py").read_text()
