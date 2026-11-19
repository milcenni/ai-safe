import os

import pytest
from typer.testing import CliRunner

from ai_safe.cli import app
from ai_safe.config import AISafeConfig
from ai_safe.credential_map import CredentialMap
from ai_safe.scanner import Scanner
from ai_safe.verifier import candidate_tokens, verify_workspace
from conftest import builtin_config, prepare, write


def codes(report):
    return {i.code for i in report.issues if i.severity.blocking}


def reverify(p, cfg=None):
    cfg = cfg or p.cfg
    cmap = CredentialMap.load(p.session.state_path)
    scanner = p.scanner if cfg is p.cfg else Scanner(cfg, p.salt)
    return verify_workspace(p.ws, cfg, scanner, original_repo=p.repo, fingerprints=cmap.fingerprints())


@pytest.fixture
def prepared(make_repo, fake):
    repo = make_repo({"app.py": f'API_KEY = "{fake.openai()}"\n', "c.yaml": f"password: {fake.password()}\n"})
    return prepare(repo)


def test_clean_workspace_passes(prepared):
    assert prepared.verification.passed
    assert prepared.verification.files_scanned > 0


def test_detects_injected_secret_in_hidden_file(prepared, fake):
    write(prepared.ws, {".hidden/config.py": f'GITHUB_TOKEN = "{fake.github()}"\n'})
    r = reverify(prepared)
    assert not r.passed and "unresolved-secret" in codes(r)


def test_detects_private_key(prepared, fake):
    write(prepared.ws, {"scripts/key.txt": fake.private_key() + "\n"})
    assert "private-key" in codes(reverify(prepared))


def test_detects_symlink_escaping_workspace(prepared, tmp_path):
    os.symlink(tmp_path, prepared.ws / "escape")
    r = reverify(prepared)
    assert "symlink-escape" in codes(r)


def test_detects_internal_symlink_when_rejected(prepared):
    os.symlink("app.py", prepared.ws / "alias.py")
    assert "symlink" in codes(reverify(prepared))


def test_detects_git_metadata(prepared):
    (prepared.ws / "sub" / ".git").mkdir(parents=True)
    (prepared.ws / "vendored").mkdir()
    (prepared.ws / "vendored" / ".git").write_text("gitdir: /somewhere/else\n")
    bare = prepared.ws / "copy.git"
    (bare / "objects").mkdir(parents=True)
    (bare / "refs").mkdir()
    (bare / "HEAD").write_text("ref: refs/heads/main\n")
    r = reverify(prepared)
    paths = {i.path for i in r.issues if i.code == "git-metadata"}
    assert {"sub/.git", "vendored/.git", "copy.git"} <= paths


def test_detects_credential_files_and_unexpected_binary(prepared):
    write(prepared.ws, {".env": "X=1\n", "nested/.aws/credentials": "[default]\n"})
    (prepared.ws / "tool.exe").write_bytes(b"MZ\x00\x00\x01")
    r = reverify(prepared)
    assert {"credential-file", "unexpected-binary"} <= codes(r)


def test_known_secret_detected_without_any_pattern(make_repo):
    # A low-entropy password is only detectable in context; once copied
    # elsewhere without a key, only the keyed fingerprint check finds it.
    repo = make_repo({"c.yaml": "password: hunter2hunter\n"})
    p = prepare(repo)
    assert p.verification.passed
    write(p.ws, {"notes.txt": "the old one was hunter2hunter, fyi\n"})
    r = reverify(p)
    assert "known-secret" in codes(r)
    assert all("hunter2hunter" not in i.message for i in r.issues)


def test_candidate_tokens():
    toks = candidate_tokens('url = "postgres://u:pa55word@h/db"; x=abcdef1')
    assert "pa55word" in toks and "abcdef1" in toks


def test_cli_verify_nonzero_on_failure(prepared, fake, monkeypatch, tmp_path):
    cfg = tmp_path / "builtin.yaml"
    cfg.write_text("version: 1\nscanner:\n  engine: builtin\n")
    monkeypatch.chdir(prepared.ws)
    ok = CliRunner().invoke(app, ["verify", "-c", str(cfg)])
    assert ok.exit_code == 0, ok.output
    write(prepared.ws, {"leak.py": f'STRIPE = "{fake.stripe()}"\n'})
    res = CliRunner().invoke(app, ["verify", "-c", str(cfg)])
    assert res.exit_code == 1, res.output
    assert "FAILED" in res.output


@pytest.mark.gitleaks
def test_gitleaks_verification_ignores_planted_allowlists(make_repo, fake, gitleaks_bin):
    repo = make_repo({"a.py": "x=1\n"})
    p = prepare(repo, AISafeConfig())
    assert p.verification.passed
    tok = fake.github()
    # AI plants a gitleaks config + ignore file + inline allow comment
    write(p.ws, {
        "src/leak.go": f'var t = "{tok}" // gitleaks:allow\n',
        ".gitleaks.toml": '[allowlist]\npaths = [".*"]\n',
        ".gitleaksignore": "src/leak.go:github-pat:1\n",
    })
    cfg = AISafeConfig()
    cfg.scanner.builtin_rules = False  # prove gitleaks alone still catches it
    r = reverify(p, cfg)
    assert any(i.code == "gitleaks" and i.path == "src/leak.go" for i in r.issues)
