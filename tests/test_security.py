import io
import json
import os
import re
import stat
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from ai_safe.cli import app
from ai_safe.config import ConfigError, load_config, parse_config
from ai_safe.detectors import BuiltinDetector
from ai_safe.security import (
    RedactingStream,
    Redactor,
    SecurityError,
    safe_join,
    safe_relpath,
    secure_mkdtemp,
    secure_remove_tree,
    write_private_file,
)
from ai_safe.workspace import SKILL_NAMES, SessionStore, skill_template, state_root
from conftest import PROJECT_ROOT, all_text, prepare, write


@pytest.mark.parametrize("bad", ["", "/abs", "../x", "a/../../b", "a\\b", "a\x00b", "C:/x", "a/\nb"])
def test_safe_relpath_rejects(bad):
    with pytest.raises(SecurityError):
        safe_relpath(bad)


def test_safe_relpath_normalises():
    assert str(safe_relpath("./a//b/./c.py")) == "a/b/c.py"


def test_safe_join_rejects_symlinked_component(tmp_path):
    root = tmp_path / "root"
    (root / "real").mkdir(parents=True)
    os.symlink(tmp_path, root / "link")
    assert safe_join(root, "real/x.py") == (root / "real/x.py").resolve()
    with pytest.raises(SecurityError):
        safe_join(root, "link/x.py")
    with pytest.raises(SecurityError):
        safe_join(root, "../escape")


def test_secure_tempdir_and_private_files(tmp_path):
    d = secure_mkdtemp("ai-safe-test-", tmp_path)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    p = d / "f.json"
    write_private_file(p, "{}")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    os.symlink(tmp_path / "target", d / "link")
    with pytest.raises(SecurityError):
        write_private_file(d / "link", "x")
    with pytest.raises(SecurityError):
        secure_mkdtemp("bad/prefix")


def test_temp_names_never_contain_secrets(make_repo, fake):
    key = fake.openai()
    repo = make_repo({"a.py": f'API_KEY = "{key}"\n'})
    p = prepare(repo)
    names = [str(x) for x in p.ws.rglob("*")] + [str(x) for x in p.session.state_path.rglob("*")]
    assert all(key not in n for n in names)
    assert key not in str(p.ws)


def test_redactor_and_stream():
    r = Redactor()
    r.add("SuperSecretValue123")
    r.add("abc")  # too short: ignored
    assert r.redact("x SuperSecretValue123 y") == "x [REDACTED] y"
    buf = io.StringIO()
    RedactingStream(buf, r).write("leak SuperSecretValue123!")
    assert buf.getvalue() == "leak [REDACTED]!"


def test_secure_remove_tree_does_not_follow_symlinks(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    d = tmp_path / "doomed"
    d.mkdir()
    (d / "f").write_text("x")
    os.symlink(victim, d / "link")
    secure_remove_tree(d, shred=True)
    assert not d.exists() and (victim / "keep.txt").read_text() == "keep"


@pytest.mark.parametrize("snippet,msg", [
    ({"integration": {"auto_push": True}}, "auto_push"),
    ({"integration": {"auto_commit": True}}, "auto_commit"),
    ({"integration": {"require_approval": False}}, "require_approval"),
    ({"workspace": {"include_git_history": True}}, "include_git_history"),
    ({"security": {"fail_closed": False}}, "fail_closed"),
    ({"security": {"store_secret_values": True, "encrypt_mapping": False}}, "encrypt_mapping"),
    ({"scanner": {"engine": "magic"}}, "engine"),
    ({"scanner": {"unknown_key": 1}}, "unknown_key"),
    ({"scanner": {"history_log_opts": "--all; rm -rf /"}}, "history_log_opts"),
    ({"scanner": {"history_log_opts": "--all --output=/tmp/x"}}, "history_log_opts"),
    ({"scanner": {"history_log_opts": "--outp=/tmp/x"}}, "history_log_opts"),
    ({"scanner": {"history_log_opts": "--all -o/tmp/x"}}, "history_log_opts"),
    ({"scanner": {"custom_rules": [{"id": "x1", "regex": "("}]}}, "invalid regex"),
    ({"version": 2}, "version"),
    ({"scanner": {"scan_ignored": False}, "sanitization": {"include_ignored_files": True}}, "include_ignored_files"),
    ({"security": {"docker_image": "bad image;rm"}}, "invalid image reference"),
    ({"security": {"docker_image": "--privileged"}}, "invalid image reference"),
    ({"security": {"docker_image": "-v"}}, "invalid image reference"),
    ({"security": {"docker_image": ""}}, "invalid image reference"),
])
def test_config_validation_rejects_unsafe(snippet, msg):
    with pytest.raises(ConfigError) as exc:
        parse_config({"version": 1, **snippet})
    assert msg in str(exc.value)


def test_docker_image_and_install_excludes():
    cfg = parse_config({"version": 1, "security": {"docker_image": "ghcr.io/acme/claude:1.2"}})
    assert cfg.security.docker_image == "ghcr.io/acme/claude:1.2"
    assert ".claude/ai-safe/" in cfg.sanitization.all_excludes()
    assert ".ai-safe/" in cfg.sanitization.all_excludes()


def test_repository_config_template_is_valid():
    cfg = load_config(PROJECT_ROOT / "ai-safe.yaml")
    assert cfg.integration.auto_push is False and cfg.workspace.include_git_history is False
    spec_example = yaml.safe_load(
        "version: 1\nscanner:\n  engine: gitleaks\n  scan_git_history: true\n  scan_untracked: true\n  scan_ignored: true\n"
        "sanitization:\n  exclude: [.env, .env.*, '*.pem', '*.key', credentials.json, secrets/, .ssh/]\n"
        "  placeholders: {enabled: true, deterministic: true}\n"
        "workspace: {isolated: true, include_git_history: false, verify_before_ai_access: true}\n"
        "integration: {require_approval: true, auto_commit: false, auto_push: false}\n"
        "security: {fail_closed: true, redact_logs: true, reject_symlinks: true}\n"
    )
    parse_config(spec_example)


def test_cleanup_removes_workspace_and_state(make_repo, fake):
    repo = make_repo({"a.py": f'API_KEY = "{fake.openai()}"\n'})
    p = prepare(repo)
    ws, st = p.ws, p.session.state_path
    removed = p.store.cleanup(p.session)
    assert not ws.exists() and not st.exists() and len(removed) == 2
    assert repo.exists() and (repo / "a.py").exists()


def test_cleanup_refuses_foreign_directories(make_repo, tmp_path):
    repo = make_repo()
    p = prepare(repo)
    s = p.session
    s.workspace = str(repo)  # tampered session pointing at the original repo
    with pytest.raises(SecurityError):
        p.store.cleanup(s)
    assert repo.exists()
    other = tmp_path / "ai-safe-ws-fake"
    other.mkdir()
    (other / ".ai-safe-workspace.json").write_text(json.dumps({"session_id": "deadbeef"}))
    s.workspace = str(other)
    with pytest.raises(SecurityError):
        p.store.cleanup(s)
    assert other.exists()


def test_cli_cleanup(make_repo, monkeypatch):
    repo = make_repo()
    p = prepare(repo)
    monkeypatch.chdir(repo)
    res = CliRunner().invoke(app, ["cleanup", "--yes"])
    assert res.exit_code == 0, res.output
    assert not p.ws.exists()


def test_state_dir_permissions(tmp_path):
    root = state_root()
    assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
    store = SessionStore(root)
    salt_file = next((root / "repos").glob("*/salt"), None) if (root / "repos").exists() else None
    store.repo_salt(tmp_path)
    salt_file = next((root / "repos").glob("*/salt"))
    assert stat.S_IMODE(os.stat(salt_file).st_mode) == 0o600


def test_cli_start_end_to_end_output_has_no_secrets(make_repo, fake, tmp_path):
    key, pw, tok = fake.openai(), fake.password(), fake.github()
    repo = make_repo({"a.py": f'API_KEY = "{key}"\n', "c.yaml": f"password: {pw}\n", "old.py": f'T = "{tok}"\n'})
    (repo / "old.py").unlink()
    cfg = tmp_path / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    res = CliRunner().invoke(app, ["start", str(repo), "-c", str(cfg)])
    assert res.exit_code == 0, res.output
    for s in (key, pw, tok):
        assert s not in res.output
    assert "ROTATE" in res.output and "AI-safe workspace ready" in res.output
    ws = Path(re.search(r"Workspace : (\S+)", res.output).group(1))
    assert ws.is_dir() and key not in all_text(ws)
    for f in (Path(os.environ["AI_SAFE_STATE_DIR"])).rglob("*"):
        if f.is_file() and "snapshot" not in f.parts and f.name != "salt":
            t = f.read_bytes().decode("utf-8", "replace")
            assert key not in t and pw not in t and tok not in t, f


def test_start_fails_closed_and_removes_workspace(make_repo, tmp_path, monkeypatch):
    repo = make_repo({"a.py": "x=1\n"})
    cfg = tmp_path / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    import ai_safe.cli as cli_mod

    real = cli_mod.verify_workspace

    def failing(*a, **kw):
        r = real(*a, **kw)
        from ai_safe.models import Severity

        r.add(Severity.CRITICAL, "test", "x", "forced failure")
        return r

    monkeypatch.setattr(cli_mod, "verify_workspace", failing)
    res = CliRunner().invoke(app, ["start", str(repo), "-c", str(cfg)])
    assert res.exit_code == 1 and "securely removed" in res.output
    base = Path(os.environ["AI_SAFE_WORKSPACE_BASE"])
    assert not any(base.glob("ai-safe-ws-*"))


def test_launch_refused_unless_configured(make_repo, tmp_path):
    repo = make_repo({"a.py": "x=1\n"})
    cfg = tmp_path / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    res = CliRunner().invoke(app, ["start", str(repo), "-c", str(cfg), "--launch"])
    assert res.exit_code == 2 and "allow_ai_launch is false" in res.output


# ---------------------------------------------------------------------------
# Skills
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_skills_complete_and_in_sync(name):
    text = skill_template(name)
    m = re.match(r"^---\nname: (.+)\ndescription: (.+)\n---\n", text)
    assert m and m.group(1) == name and len(m.group(2)) > 40
    for section in ("Execution boundaries", "Failure conditions"):
        assert section in text, (name, section)
    assert "Expected inputs" in text and "Outputs" in text
    assert (PROJECT_ROOT / "skills" / name / "SKILL.md").read_text() == text
    # skills must never trip the detector themselves
    assert BuiltinDetector().scan_text(text, f"{name}/SKILL.md") == []


def test_main_skill_covers_required_rules():
    t = skill_template("ai-safe").lower()
    for phrase in (".ai-safe-workspace.json", "never request", "parent directories", "outside this workspace",
                   "environment", "hardcode", ".env", "recover", "ai-safe verify", "placeholder requirement",
                   "not a security boundary"):
        assert phrase in t, phrase


def test_skills_install_cli(tmp_path):
    res = CliRunner().invoke(app, ["skills", "install", str(tmp_path)])
    assert res.exit_code == 0
    assert all((tmp_path / ".claude/skills" / n / "SKILL.md").is_file() for n in SKILL_NAMES)
