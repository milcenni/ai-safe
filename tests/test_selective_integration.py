"""`ai-safe integrate --only/--select`: integrate only selected files (synthetic values only)."""

import hashlib
import json
import os

import pytest
from typer.testing import CliRunner

from ai_safe import cli
from ai_safe.cli import app
from ai_safe.integration import integrate
from ai_safe.resync import pending_changes, resync
from ai_safe.review import overlay_name, review_session
from ai_safe.security import SecurityError
from ai_safe.selection import Row, build_rows, parse_selection, path_matches, selected_paths
from ai_safe.workspace import Session, tree_hash
from conftest import prepare, write

APPROVE = lambda rr, patch: True  # noqa: E731


@pytest.fixture
def project(make_repo, fake):
    key, pw = fake.openai(), fake.password()
    repo = make_repo({
        ".gitignore": ".env\n",
        "app/settings.py": f'import os\n\nAPI_KEY = "{key}"\nDB_PASSWORD = "{pw}"\nDEBUG = False\n\n\ndef hello():\n    return "hi"\n',
        "app/util.py": "def add(a, b):\n    return a + b\n",
        "app/lib/one.py": "ONE = 1\n",
        "app/lib/two.py": "TWO = 2\n",
        "app/Controllers/Home.php": "<?php\nclass Home {}\n",
        "app/Controllers/sub/Deep.php": "<?php\nclass Deep {}\n",
        "app/Models/User.php": "<?php\nclass User {}\n",
        "README.md": "# demo\n",
    })
    write(repo, {".env": f"DB_PASSWORD={pw}\n"})
    p = prepare(repo)
    assert p.verification.passed
    p.key, p.pw = key, pw
    return p


def edit(p, rel, old, new):
    f = p.ws / rel
    text = f.read_text()
    assert old in text
    f.write_text(text.replace(old, new))


def run_integrate(p, **kw):
    return integrate(p.session, p.cfg, p.scanner, confirm=kw.pop("confirm", APPROVE), cwd=p.repo, **kw)


def touch_all(p):
    """AI changes in several places (none blocking)."""
    edit(p, "app/util.py", "return a + b", "return a + b  # util")
    edit(p, "app/lib/one.py", "ONE = 1", "ONE = 11")
    edit(p, "app/lib/two.py", "TWO = 2", "TWO = 22")
    edit(p, "app/Controllers/Home.php", "class Home {}", "class Home { }")
    edit(p, "app/Controllers/sub/Deep.php", "class Deep {}", "class Deep { }")
    edit(p, "app/Models/User.php", "class User {}", "class User { }")


def changed_in_repo(p) -> set[str]:
    out = set()
    for rel, marker in (("app/util.py", "# util"), ("app/lib/one.py", "11"), ("app/lib/two.py", "22"),
                        ("app/Controllers/Home.php", "{ }"), ("app/Controllers/sub/Deep.php", "{ }"),
                        ("app/Models/User.php", "{ }")):
        if marker in (p.repo / rel).read_text():
            out.add(rel)
    return out


def cfg_file(p):
    cfg = p.repo.parent / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    return cfg


# ---------------------------------------------------------------------------
# --only matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern,path,expected", [
    ("app/util.py", "app/util.py", True),
    ("./app/util.py", "app/util.py", True),
    ("app/util", "app/util.py", False),
    ("app/lib/", "app/lib/one.py", True),
    ("app/lib", "app/lib/one.py", True),
    ("app/li", "app/lib/one.py", False),
    ("app/Controllers/*.php", "app/Controllers/Home.php", True),
    ("app/Controllers/*.php", "app/Controllers/sub/Deep.php", False),
    ("app/Controllers/*.php", "x/app/Controllers/Home.php", False),
    ("app/**/*.php", "app/Controllers/sub/Deep.php", True),
    ("app/*", "app/lib/one.py", True),  # a glob matching a directory selects what is below it
    ("*.md", "README.md", True),
    ("*.md", "docs/a.md", False),
])
def test_path_matches(pattern, path, expected):
    assert path_matches(pattern, path) is expected


def test_only_file(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/util.py",))
    assert not res.aborted, res.reason
    assert res.applied == ["app/util.py"]
    assert changed_in_repo(project) == {"app/util.py"}
    assert "app/lib/one.py" in res.left_in_workspace and "app/util.py" not in res.left_in_workspace


def test_only_directory_prefix(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/lib/",))
    assert not res.aborted, res.reason
    assert changed_in_repo(project) == {"app/lib/one.py", "app/lib/two.py"}


def test_only_glob(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/Controllers/*.php",))
    assert not res.aborted, res.reason
    assert changed_in_repo(project) == {"app/Controllers/Home.php"}


def test_only_repeatable(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/util.py", "app/Models/"))
    assert not res.aborted, res.reason
    assert changed_in_repo(project) == {"app/util.py", "app/Models/User.php"}


def test_exclude_wins_over_only(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/",), exclude_paths=("app/lib/",))
    assert not res.aborted, res.reason
    assert changed_in_repo(project) == {"app/util.py", "app/Controllers/Home.php", "app/Controllers/sub/Deep.php",
                                        "app/Models/User.php"}


def test_only_pattern_matching_nothing_is_an_error(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/util.py", "app/utill.py"))
    assert res.aborted and res.usage_error and "app/utill.py" in res.reason
    assert changed_in_repo(project) == set()


def test_only_and_select_cannot_be_combined(project):
    with pytest.raises(ValueError):
        run_integrate(project, only_paths=("app/util.py",), select=lambda rr: {"app/util.py"})


# ---------------------------------------------------------------------------
# blocking rules
# ---------------------------------------------------------------------------


def test_error_in_unselected_file_does_not_block(project, fake):
    touch_all(project)
    write(project.ws, {"app/leak.py": f'GITHUB_TOKEN = "{fake.github()}"\n'})
    res = run_integrate(project, only_paths=("app/util.py",))
    assert not res.aborted, res.reason
    assert res.applied == ["app/util.py"]
    assert any(i.code == "hardcoded-credential" and i.path == "app/leak.py" for i in res.review.issues)
    assert not (project.repo / "app/leak.py").exists()


def test_same_error_in_selected_file_blocks(project, fake):
    touch_all(project)
    write(project.ws, {"app/leak.py": f'GITHUB_TOKEN = "{fake.github()}"\n'})
    res = run_integrate(project, only_paths=("app/util.py", "app/leak.py"))
    assert res.aborted and res.reason == "review found blocking issues"
    assert not (project.repo / "app/leak.py").exists() and changed_in_repo(project) == set()


@pytest.mark.parametrize("only", [("app/util.py",), (".ai-safe/",)])
def test_install_path_blocks_whether_selected_or_not(project, only):
    touch_all(project)
    write(project.ws, {".ai-safe/bin/ai-safe": "echo changed\n"})
    res = run_integrate(project, only_paths=only)
    assert res.aborted and res.reason == "review found blocking issues"
    assert any(i.code == "ai-safe-install" for i in res.review.issues)
    assert changed_in_repo(project) == set()


def test_install_path_blocks_picker_before_prompt(project):
    touch_all(project)
    write(project.ws, {".ai-safe/bin/ai-safe": "echo changed\n"})
    called = []
    res = run_integrate(project, select=lambda rr: called.append(1) or {"app/util.py"})
    assert res.aborted and not called


def test_marker_tampering_blocks_partial_integration(project):
    touch_all(project)
    (project.ws / ".ai-safe-workspace.json").write_text("{}")
    res = run_integrate(project, only_paths=("app/util.py",))
    assert res.aborted and any(i.code == "marker-tampered" for i in res.review.issues)


# ---------------------------------------------------------------------------
# renames, dependencies, record
# ---------------------------------------------------------------------------


def test_rename_pair_selected_from_one_side_applies_both(project):
    os.rename(project.ws / "app/util.py", project.ws / "app/helpers.py")
    edit(project, "app/lib/one.py", "ONE = 1", "ONE = 11")
    res = run_integrate(project, only_paths=("app/helpers.py",))
    assert not res.aborted, res.reason
    assert (project.repo / "app/helpers.py").read_text() == "def add(a, b):\n    return a + b\n"
    assert not (project.repo / "app/util.py").exists()
    assert res.applied == ["app/helpers.py"] and res.deleted == ["app/util.py"]
    assert "ONE = 1\n" == (project.repo / "app/lib/one.py").read_text()


def test_rename_pair_selected_from_deleted_side(project):
    os.rename(project.ws / "app/util.py", project.ws / "app/helpers.py")
    edit(project, "app/helpers.py", "return a + b", "return a + b  # moved")  # similar, not identical
    res = run_integrate(project, only_paths=("app/util.py",))
    assert not res.aborted, res.reason
    assert "# moved" in (project.repo / "app/helpers.py").read_text()
    assert not (project.repo / "app/util.py").exists()


def test_rename_is_one_row_in_picker(project):
    os.rename(project.ws / "app/util.py", project.ws / "app/helpers.py")
    rows = build_rows(review_session(project.session, project.cfg, project.scanner))
    assert [(r.status, r.label) for r in rows] == [("renamed", "app/util.py -> app/helpers.py")]
    assert set(rows[0].paths) == {"app/util.py", "app/helpers.py"}


def test_dependency_warning_php(project):
    write(project.ws, {"app/Libraries/RateLimiter.php": "<?php\nnamespace App\\Libraries;\nclass RateLimiter {}\n",
                       "app/helpers/limits.php": "<?php\nfunction limits() { return 1; }\n"})
    edit(project, "app/Controllers/Home.php", "class Home {}",
         "use App\\Libraries\\RateLimiter;\nrequire_once __DIR__ . '/../helpers/limits.php';\nclass Home {}")
    res = run_integrate(project, only_paths=("app/Controllers/Home.php",), dry_run=True)
    deps = {i.message.split()[1].rstrip(",") for i in res.review.issues if i.code == "unselected-dependency"}
    assert deps == {"app/Libraries/RateLimiter.php", "app/helpers/limits.php"}
    assert all(i.severity.value == "WARNING" for i in res.review.issues if i.code == "unselected-dependency")
    # selecting the dependency too removes the warning
    res = run_integrate(project, only_paths=("app/Controllers/Home.php", "app/Libraries/", "app/helpers/"), dry_run=True)
    assert not [i for i in res.review.issues if i.code == "unselected-dependency"]


def test_dependency_warning_js(project):
    write(project.ws, {"web/src/api.ts": "export const api = 1;\n",
                       "web/src/main.ts": "import { api } from './api';\nimport React from 'react';\nconsole.log(api);\n"})
    res = run_integrate(project, only_paths=("web/src/main.ts",), dry_run=True)
    assert [i.message.split()[1].rstrip(",") for i in res.review.issues if i.code == "unselected-dependency"] == ["web/src/api.ts"]
    assert res.reason == "dry run" and not (project.repo / "web/src/main.ts").exists()


def test_dry_run_patch_has_selection_only(project):
    touch_all(project)
    res = run_integrate(project, only_paths=("app/util.py",), dry_run=True)
    assert res.reason == "dry run"
    record = open(res.patch_path).read()
    assert "#   selected: app/util.py" in record
    assert "#   left in workspace: app/lib/one.py" in record
    body = "".join(ln for ln in record.splitlines(True) if not ln.startswith("#"))
    assert "app/util.py" in body and "app/lib/one.py" not in body
    assert changed_in_repo(project) == set()


# ---------------------------------------------------------------------------
# picker
# ---------------------------------------------------------------------------


ROWS = [Row("modified", "a.py", ("a.py",)), Row("added", "b.py", ("b.py",)),
        Row("deleted", "c.py", ("c.py",)), Row("renamed", "d.py -> e.py", ("d.py", "e.py")),
        Row("modified", "f.py", ("f.py",)), Row("modified", "logo.png", ("logo.png",), "manual", selectable=False)]


@pytest.mark.parametrize("text,expected", [
    ("1,3-5", {1, 3, 4, 5}),
    (" 2 , 4 ", {2, 4}),
    ("1-1", {1}),
    ("all", {1, 2, 3, 4, 5}),
    ("ALL", {1, 2, 3, 4, 5}),
    ("none", set()),
])
def test_parse_selection_valid(text, expected):
    indexes, error = parse_selection(text, ROWS)
    assert error is None and indexes == expected


@pytest.mark.parametrize("text", ["", "0", "7", "1,7", "3-1", "abc", "1;2", "1,,2", "-1", "1-", "6", "5-6"])
def test_parse_selection_invalid(text):
    indexes, error = parse_selection(text, ROWS)
    assert indexes is None and error


def test_selected_paths_expand_rename_row():
    assert selected_paths({1, 4}, ROWS) == {"a.py", "d.py", "e.py"}


def test_picker_rows_mark_manual_and_metadata_unselectable(project):
    edit(project, "app/util.py", "return a + b", "return b + a")
    os.chmod(project.ws / "README.md", 0o755)  # mode-only: manual
    write(project.ws, {".claude/settings.local.json": "{}\n"})
    rows = {r.label: r for r in build_rows(review_session(project.session, project.cfg, project.scanner))}
    assert rows["app/util.py"].selectable
    assert not rows["README.md"].selectable and "manual" in rows["README.md"].review
    assert not rows[".claude/settings.local.json"].selectable


def test_cli_select_reprompts_until_valid(project, monkeypatch):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.chdir(project.repo)
    rows = build_rows(review_session(project.session, project.cfg, project.scanner))
    util_row = next(n for n, r in enumerate(rows, 1) if r.label == "app/util.py")
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--select"],
                           input=f"garbage\n99\n\n{util_row}\napply\n")
    assert r.exit_code == 0, r.output
    assert r.output.count("Invalid selection") == 3
    assert changed_in_repo(project) == {"app/util.py"}
    report = json.loads((project.session.reports_dir / "integration.json").read_text())
    assert report["selected"] == ["app/util.py"] and report["applied"] == ["app/util.py"]
    assert "app/lib/one.py" in report["left_in_workspace"]
    assert project.key not in r.output and project.pw not in r.output


def test_cli_select_none_integrates_nothing(project, monkeypatch):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--select"], input="none\n")
    assert r.exit_code == 0, r.output
    assert "nothing selected" in r.output and changed_in_repo(project) == set()


def test_cli_select_refuses_without_tty(project, monkeypatch):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--select"], input="all\napply\n")
    assert r.exit_code == 2 and "interactive terminal" in r.output
    assert changed_in_repo(project) == set()


def test_cli_only_and_select_conflict(project, monkeypatch):
    cfg = cfg_file(project)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--select", "--only", "app/util.py"])
    assert r.exit_code == 2 and "cannot be combined" in r.output


def test_cli_only_matching_nothing_exits_usage(project, monkeypatch):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--only", "no/such/file.py"], input="apply\n")
    assert r.exit_code == 2, r.output
    assert "matched no changed file" in r.output and changed_in_repo(project) == set()


def test_cli_only_writes_integration_record(project, monkeypatch):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), "--only", "app/lib/"], input="apply\n")
    assert r.exit_code == 0, r.output
    report = json.loads((project.session.reports_dir / "integration.json").read_text())
    assert report["selected"] == ["app/lib/one.py", "app/lib/two.py"]
    assert "app/util.py" in report["left_in_workspace"]
    patch = open(report["patch"]).read()
    assert "#   left in workspace: app/util.py" in patch
    assert "left in the workspace" in r.output


@pytest.mark.parametrize("args", [["--only", "app/util.py"], ["--select"]])
def test_cli_integrate_refuses_in_ai_agent_env(project, monkeypatch, args):
    cfg = cfg_file(project)
    touch_all(project)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["integrate", "-c", str(cfg), *args], input="all\napply\n")
    assert r.exit_code == 3 and "developer" in r.output
    assert changed_in_repo(project) == set()


@pytest.mark.parametrize("kw", [{"only_paths": ("app/util.py",)}, {"select": lambda rr: {"app/util.py"}}])
def test_library_integrate_refuses_in_ai_agent_env(project, monkeypatch, kw):
    touch_all(project)
    monkeypatch.setenv("CLAUDECODE", "1")
    with pytest.raises(SecurityError, match="AI agent"):
        run_integrate(project, **kw)
    assert changed_in_repo(project) == set()


# ---------------------------------------------------------------------------
# state: second integrate and resync
# ---------------------------------------------------------------------------


def test_partial_then_rest_no_original_changed(project):
    touch_all(project)
    edit(project, "app/settings.py", 'return "hi"', 'return "hello"')
    first = run_integrate(project, only_paths=("app/util.py", "app/settings.py"))
    assert not first.aborted, first.reason
    loaded = Session.load(project.session.state_path)
    assert set(loaded.integrated_files) == {"app/util.py", "app/settings.py"}
    assert loaded.integrated_tree_hash is None
    written = (project.repo / "app/settings.py").read_bytes()
    # keyed digest, never a plain hash of content that holds real credentials
    assert loaded.integrated_files["app/settings.py"] != hashlib.sha256(written).hexdigest()
    rr = review_session(project.session, project.cfg, project.scanner)
    assert "app/util.py" not in {c.path for c in rr.changes}
    assert not [i for i in rr.issues if i.code == "original-changed"], rr.public()
    second = run_integrate(project)
    assert not second.aborted, (second.reason, second.review.public())
    assert "app/util.py" not in second.applied and "app/settings.py" not in second.applied
    assert changed_in_repo(project) == {"app/util.py", "app/lib/one.py", "app/lib/two.py", "app/Controllers/Home.php",
                                        "app/Controllers/sub/Deep.php", "app/Models/User.php"}
    s = (project.repo / "app/settings.py").read_text()
    assert f'API_KEY = "{project.key}"' in s and 'return "hello"' in s and "AI_SAFE_SECRET" not in s
    assert Session.load(project.session.state_path).integrated_tree_hash == tree_hash(project.ws)
    assert pending_changes(project.session) == []


def test_changed_again_after_integration_compares_against_integrated(project):
    edit(project, "app/settings.py", 'return "hi"', 'return "hello"')
    edit(project, "app/util.py", "return a + b", "return a + b  # util")
    assert not run_integrate(project, only_paths=("app/settings.py",)).aborted
    edit(project, "app/settings.py", "DEBUG = False", "DEBUG = True")  # AI keeps working on it
    rr = review_session(project.session, project.cfg, project.scanner)
    assert {c.path for c in rr.changes} == {"app/settings.py", "app/util.py"}
    assert not [i for i in rr.issues if i.severity.blocking], rr.public()
    res = run_integrate(project, only_paths=("app/settings.py",))
    assert not res.aborted, (res.reason, res.review.public())
    s = (project.repo / "app/settings.py").read_text()
    assert 'return "hello"' in s and "DEBUG = True" in s
    assert f'API_KEY = "{project.key}"' in s and f'DB_PASSWORD = "{project.pw}"' in s
    assert "# util" not in (project.repo / "app/util.py").read_text()


def test_developer_edit_after_partial_integration_is_original_changed(project):
    edit(project, "app/util.py", "return a + b", "return a + b  # util")
    assert not run_integrate(project, only_paths=("app/util.py",)).aborted
    edit(project, "app/util.py", "# util", "# util again")
    (project.repo / "app/util.py").write_text("def add(a, b):\n    return 0\n")  # developer edits original
    rr = review_session(project.session, project.cfg, project.scanner)
    assert any(i.code == "original-changed" and i.path == "app/util.py" for i in rr.issues)


def test_partial_deletion_then_rest(project):
    (project.ws / "README.md").unlink()
    edit(project, "app/util.py", "return a + b", "return 1")
    res = run_integrate(project, only_paths=("README.md",))
    assert not res.aborted and res.deleted == ["README.md"]
    assert Session.load(project.session.state_path).integrated_files["README.md"] == "deleted"
    assert [c.path for c in pending_changes(project.session)] == ["app/util.py"]
    res = run_integrate(project)
    assert not res.aborted, res.reason
    assert res.applied == ["app/util.py"] and res.deleted == []


def test_integrated_file_not_shown_in_picker(project):
    touch_all(project)
    assert not run_integrate(project, only_paths=("app/util.py",)).aborted
    rows = build_rows(review_session(project.session, project.cfg, project.scanner))
    assert "app/util.py" not in {r.label for r in rows}


def test_missing_integrated_baseline_fails_closed(project):
    edit(project, "app/util.py", "return a + b", "return a + b  # util")
    edit(project, "app/lib/one.py", "ONE = 1", "ONE = 11")
    assert not run_integrate(project, only_paths=("app/util.py",)).aborted
    (project.session.integrated_dir / overlay_name("app/util.py")).unlink()
    rr = review_session(project.session, project.cfg, project.scanner)
    assert any(i.code == "original-changed" and i.path == "app/util.py" for i in rr.issues)
    assert [c.path for c in pending_changes(project.session)] == ["app/lib/one.py", "app/util.py"]


def test_only_covering_everything_records_integrated_hash(project):
    edit(project, "app/util.py", "return a + b", "return b + a")
    res = run_integrate(project, only_paths=("app/",))
    assert not res.aborted, res.reason
    assert Session.load(project.session.state_path).integrated_tree_hash == tree_hash(project.ws)


def resync_run(p, discard=False):
    return resync(p.session, p.cfg, p.store, p.scanner, p.salt, discard=discard, passphrase=None)


def test_partial_then_resync_refuses_until_everything_integrated(project):
    edit(project, "app/util.py", "return a + b", "return b + a")
    edit(project, "app/lib/one.py", "ONE = 1", "ONE = 11")
    assert not run_integrate(project, only_paths=("app/util.py",)).aborted
    assert [c.path for c in pending_changes(project.session)] == ["app/lib/one.py"]
    out = resync_run(project)
    assert not out.ok and "resync --discard" in out.reason
    assert not run_integrate(project, only_paths=("app/lib/one.py",)).aborted
    assert pending_changes(project.session) == []
    out = resync_run(project)
    assert out.ok, out.reason
    loaded = Session.load(project.session.state_path)
    assert loaded.integrated_files == {} and not project.session.integrated_dir.exists()
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return b + a\n"
    assert pending_changes(loaded) == []
    # the next integrate works against the rebuilt snapshot
    edit(project, "app/util.py", "return b + a", "return (b + a)")
    again = run_integrate(project)
    assert not again.aborted, again.reason
    assert "(b + a)" in (project.repo / "app/util.py").read_text()


def test_cli_resync_discard_counts_non_integrated(project, monkeypatch):
    cfg = cfg_file(project)
    edit(project, "app/util.py", "return a + b", "return b + a")
    edit(project, "app/lib/one.py", "ONE = 1", "ONE = 11")
    edit(project, "app/lib/two.py", "TWO = 2", "TWO = 22")
    assert not run_integrate(project, only_paths=("app/util.py",)).aborted
    monkeypatch.chdir(project.repo)
    r = CliRunner().invoke(app, ["resync", "-c", str(cfg), "--discard"], input="no\n")
    assert r.exit_code == 1, r.output
    assert "2 workspace change(s) that were NOT integrated" in r.output
    assert "1 already-integrated file(s) are safe" in r.output
    assert "ONE = 11" in (project.ws / "app/lib/one.py").read_text()
    r = CliRunner().invoke(app, ["resync", "-c", str(cfg), "--discard"], input="discard\n")
    assert r.exit_code == 0, r.output
    assert (project.ws / "app/lib/one.py").read_text() == "ONE = 1\n"
    assert (project.ws / "app/util.py").read_text() == "def add(a, b):\n    return b + a\n"  # integrated: kept
    assert Session.load(project.session.state_path).integrated_files == {}


def test_session_without_integrated_files_loads(project):
    state = project.session.state_path
    data = json.loads((state / "session.json").read_text())
    data.pop("integrated_files", None)
    (state / "session.json").write_text(json.dumps(data))
    assert Session.load(state).integrated_files == {}
