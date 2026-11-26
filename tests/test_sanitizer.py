import json
import os
import stat

import pytest

from ai_safe.credential_map import CredentialMap
from ai_safe.models import Category
from ai_safe.redaction import PlaceholderRegistry, RedactionError, redact_text
from ai_safe.detectors import BuiltinDetector
from ai_safe.models import Finding, Location
from ai_safe.security import SecurityError
from conftest import all_text, builtin_config, git, prepare, tree_snapshot, write


def entry(res, path):
    return next(e for e in res.result.entries if e.path == path)


def test_api_key_replaced_with_deterministic_placeholder(make_repo, fake):
    key = fake.openai()
    repo = make_repo({"app.py": f'OPENAI_API_KEY = "{key}"\nprint("ok")\n'})
    p = prepare(repo)
    text = (p.ws / "app.py").read_text()
    assert text == 'OPENAI_API_KEY = "${AI_SAFE_SECRET_OPENAI_API_KEY}"\nprint("ok")\n'
    assert entry(p, "app.py").action == "sanitized"
    assert p.verification.passed


def test_same_secret_gets_same_placeholder_everywhere_and_across_runs(make_repo, fake):
    pw = fake.password()
    repo = make_repo({
        "a.yaml": f"db_password: {pw}\n",
        "b.py": f'DB_PASSWORD = "{pw}"\n',
        "docs.md": f"Legacy note mentions {pw} inline.\n",
    })
    p1 = prepare(repo)
    p2 = prepare(repo)
    for p in (p1, p2):
        assert "${AI_SAFE_SECRET_DB_PASSWORD}" in (p.ws / "a.yaml").read_text()
        assert "${AI_SAFE_SECRET_DB_PASSWORD}" in (p.ws / "b.py").read_text()
        assert "${AI_SAFE_SECRET_DB_PASSWORD}" in (p.ws / "docs.md").read_text()  # global replacement
        assert pw not in all_text(p.ws)
    assert [e.placeholder for e in p1.result.credential_map.entries] == [e.placeholder for e in p2.result.credential_map.entries]


def test_example_from_spec(make_repo, fake):
    k, pw = fake.openai(), fake.password()
    repo = make_repo({"settings.cfg": f"OPENAI_API_KEY={k}\nDB_PASSWORD={pw}\n"})
    p = prepare(repo)
    assert (p.ws / "settings.cfg").read_text() == (
        "OPENAI_API_KEY=${AI_SAFE_SECRET_OPENAI_API_KEY}\nDB_PASSWORD=${AI_SAFE_SECRET_DB_PASSWORD}\n"
    )


def test_env_files_keys_and_credential_stores_excluded(make_repo, fake):
    repo = make_repo({
        ".gitignore": ".env\n",
        "app.py": "print(1)\n",
        "deploy/id_rsa": fake.private_key() + "\n",
        "certs/server.pem": "x\n",
        "credentials.json": "{}\n",
        "secrets/prod.txt": "x\n",
        ".npmrc": "//registry/:_authToken=x\n",
        ".claude/settings.local.json": "{}\n",
        ".ai-safe/bin/ai-safe": "#!/bin/sh\n",
        ".env.production": f"DB_PASSWORD={fake.password()}\n",
    })
    write(repo, {".env": f"DB_PASSWORD={fake.password()}\n"})
    p = prepare(repo)
    for rel in ("deploy/id_rsa", "certs/server.pem", "credentials.json", "secrets/prod.txt", ".npmrc", ".env.production"):
        assert not (p.ws / rel).exists(), rel
        assert entry(p, rel).action == "excluded"
    # ai-safe's install dir is dropped by the scanner before sanitization: never copied, no manifest entry.
    assert not (p.ws / ".ai-safe").exists()
    assert not any(e.path.startswith(".ai-safe/") for e in p.result.entries)
    assert not (p.ws / ".env").exists()
    assert not (p.ws / ".claude" / "settings.local.json").exists()
    assert (p.ws / "app.py").exists()
    assert p.verification.passed


def test_ssh_private_key_file_excluded_and_embedded_key_redacted(make_repo, fake):
    key = fake.private_key("OPENSSH PRIVATE KEY")
    repo = make_repo({
        "keys/deploy": key + "\n",  # name not in exclude list: content-based detection
        "src/embedded.py": f'KEY = """{fake.private_key()}"""\nX = 1\n',
    })
    p = prepare(repo)
    assert entry(p, "keys/deploy").action == "excluded"
    assert entry(p, "keys/deploy").reason == "private key file"
    emb = (p.ws / "src/embedded.py").read_text()
    assert "PRIVATE KEY" not in emb and "${AI_SAFE_SECRET_" in emb and "X = 1" in emb
    assert p.verification.passed


def test_yaml_and_json_credentials(make_repo, fake):
    pw, sec = fake.password(), fake.aws_secret()
    repo = make_repo({
        "config/app.yaml": f"database:\n  user: app\n  password: {pw}\n",
        "config/creds.json": json.dumps({"aws_secret_access_key": sec, "region": "eu"}, indent=2),
    })
    p = prepare(repo)
    y = (p.ws / "config/app.yaml").read_text()
    j = json.loads((p.ws / "config/creds.json").read_text())
    assert "password: ${AI_SAFE_SECRET_PASSWORD}" in y
    assert j["aws_secret_access_key"].startswith("${AI_SAFE_SECRET_") and j["region"] == "eu"


def test_yaml_block_scalar_secret(make_repo, fake):
    repo = make_repo({"c.yaml": f"private_key: |\n  {fake.aws_secret()}\n  {fake.aws_secret()}\nother: 1\n"})
    p = prepare(repo)
    t = (p.ws / "c.yaml").read_text()
    assert t.startswith("private_key: |\n  ${AI_SAFE_SECRET_PRIVATE_KEY}\nother: 1")


def test_git_directory_and_history_not_copied(make_repo, fake):
    repo = make_repo({"a.py": "x=1\n"})
    p = prepare(repo)
    assert not (p.ws / ".git").exists()
    assert not any(part == ".git" for f in p.ws.rglob("*") for part in f.parts)


def test_sanitization_failure_excludes_file(make_repo):
    # Private key header without footer cannot be bounded -> fail closed
    repo = make_repo({"broken.py": 'K = "-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAK"\n', "ok.py": "y=2\n"})
    p = prepare(repo)
    e = entry(p, "broken.py")
    assert e.action == "excluded" and "fail closed" in e.reason
    assert not (p.ws / "broken.py").exists() and (p.ws / "ok.py").exists()
    assert p.verification.passed


def test_redaction_engine_fails_when_secret_not_locatable():
    f = Finding("x", Category.API_KEY, "a.py", 1, 1, "gitleaks", Location.TRACKED, secret="not-in-the-text-123")
    with pytest.raises(RedactionError) as exc:
        redact_text("hello\n", "a.py", [f], PlaceholderRegistry(b"k" * 32), BuiltinDetector())
    assert "not-in-the-text-123" not in str(exc.value)


def test_placeholders_disabled_excludes_secret_files(make_repo, fake):
    repo = make_repo({"a.py": f'API_KEY = "{fake.openai()}"\n', "b.py": "x=1\n"})
    cfg = builtin_config()
    cfg.sanitization.placeholders.enabled = False
    p = prepare(repo, cfg)
    assert entry(p, "a.py").action == "excluded" and (p.ws / "b.py").exists()


def test_manifest_and_mapping_contain_no_secrets(make_repo, fake):
    k, pw = fake.openai(), fake.password()
    repo = make_repo({"a.py": f'API_KEY = "{k}"\n', "c.yaml": f"password: {pw}\n"})
    p = prepare(repo)
    st = p.session.state_path
    for name in ("manifest.json", "credential-map.json", "session.json"):
        text = (st / name).read_text()
        assert k not in text and pw not in text
        assert stat.S_IMODE(os.stat(st / name).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(st).st_mode) == 0o700
    assert not (st / "credential-secrets.enc").exists()
    # mapping is stored outside the workspace
    assert not str(st).startswith(str(p.ws))
    assert "credential-map" not in " ".join(str(x) for x in p.ws.rglob("*"))


def test_encrypted_mapping_roundtrip(make_repo, fake):
    k = fake.openai()
    repo = make_repo({"a.py": f'API_KEY = "{k}"\n'})
    cfg = builtin_config()
    cfg.security.store_secret_values = True
    p = prepare(repo, cfg, passphrase="correct horse battery staple")
    blob = (p.session.state_path / "credential-secrets.enc").read_bytes()
    assert k.encode() not in blob
    values = CredentialMap.load_secret_values(p.session.state_path, "correct horse battery staple")
    assert values["AI_SAFE_SECRET_API_KEY"] == k
    with pytest.raises(SecurityError):
        CredentialMap.load_secret_values(p.session.state_path, "wrong")


def test_store_values_without_passphrase_fails_closed(make_repo, fake):
    repo = make_repo({"a.py": f'API_KEY = "{fake.openai()}"\n'})
    cfg = builtin_config()
    cfg.security.store_secret_values = True
    with pytest.raises(SecurityError):
        prepare(repo, cfg, passphrase=None)


def test_binary_and_symlink_handling(make_repo, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    repo = make_repo({"a.py": "x=1\n"})
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02secret?")
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    os.symlink(outside, repo / "link.txt")
    os.symlink("a.py", repo / "internal-link.py")
    p = prepare(repo)
    assert entry(p, "blob.bin").action == "excluded"
    assert entry(p, "logo.png").action == "copied"
    assert entry(p, "link.txt").action == "excluded"
    assert entry(p, "internal-link.py").action == "excluded"  # reject_symlinks default
    assert not os.path.lexists(p.ws / "link.txt")
    assert p.verification.passed


def test_permissions_preserved_safely(make_repo):
    repo = make_repo({"run.sh": "#!/bin/sh\necho hi\n", "a.py": "x=1\n"})
    os.chmod(repo / "run.sh", 0o4777)  # setuid + world-writable
    os.chmod(repo / "a.py", 0o600)
    p = prepare(repo)
    assert stat.S_IMODE(os.stat(p.ws / "run.sh").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(p.ws / "a.py").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(p.ws).st_mode) == 0o700


def test_original_repository_unchanged(make_repo, fake):
    repo = make_repo({"a.py": f'API_KEY = "{fake.openai()}"\n', "c.yaml": f"password: {fake.password()}\n"})
    write(repo, {"untracked.py": f'TOKEN = "{fake.github()}"\n'})
    before = tree_snapshot(repo)
    head = git(repo, "rev-parse", "HEAD")
    prepare(repo)
    assert tree_snapshot(repo) == before
    assert git(repo, "rev-parse", "HEAD") == head


def test_history_only_secret_replaced_if_it_reappears(make_repo, fake):
    tok = fake.github()
    repo = make_repo({"old.py": f'T = "{tok}"\n'})
    (repo / "old.py").unlink()
    write(repo, {"notes.txt": f"see {tok[:4]} and also {tok}\n"})  # value pasted without a pattern context
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "x")
    p = prepare(repo)
    assert tok not in (p.ws / "notes.txt").read_text()


def test_history_summary_is_sanitized(make_repo, fake):
    tok = fake.github()
    repo = make_repo({"a.py": "x=1\n"})
    write(repo, {"b.py": "y=2\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", f"rotate {tok}")
    cfg = builtin_config()
    cfg.sanitization.history_summary = True
    p = prepare(repo, cfg)
    s = (p.ws / "AI_SAFE_HISTORY.md").read_text()
    assert tok not in s and "b.py" in s and "t@example.invalid" not in s
    assert p.verification.passed


def test_workspace_contains_claude_integration_without_original_path(make_repo):
    repo = make_repo({"a.py": "x=1\n"})
    p = prepare(repo)
    assert (p.ws / ".claude/skills/ai-safe/SKILL.md").is_file()
    assert (p.ws / ".claude/settings.json").is_file()
    assert (p.ws / ".ai-safe-workspace.json").is_file()
    assert str(repo) not in all_text(p.ws)
