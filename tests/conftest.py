"""Shared fixtures. All credentials used in tests are SYNTHETIC and generated
at runtime; no real credential is ever used."""

from __future__ import annotations

import os
import random
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from ai_safe.config import AISafeConfig, ScannerConfig
from ai_safe.credential_map import CredentialMap
from ai_safe.gitleaks import find_gitleaks
from ai_safe.sanitizer import Sanitizer
from ai_safe.scanner import Scanner
from ai_safe.verifier import verify_workspace
from ai_safe.workspace import SessionStore, state_root

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Fake:
    """Credential-shaped synthetic values (random, never real)."""

    def __init__(self, seed: int = 0) -> None:
        self.r = random.Random(seed)

    def _s(self, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def openai(self) -> str:
        return "sk-proj-" + self._s(40)

    def github(self) -> str:
        return "ghp_" + self._s(36)

    def stripe(self) -> str:
        return "sk_live_" + self._s(24)

    def aws_key_id(self) -> str:
        return "AKIA" + self._s(16, string.ascii_uppercase + "234567")

    def aws_secret(self) -> str:
        return self._s(40, string.ascii_letters + string.digits + "+/")

    def password(self) -> str:
        return "Pw-" + self._s(14)

    def private_key(self, label: str = "RSA PRIVATE KEY") -> str:
        body = "\n".join(self._s(64, string.ascii_letters + string.digits + "+/") for _ in range(5))
        return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def short_word(rng: random.Random, n: int = 5) -> str:
    """Short lowercase value, like a weak real-world password or a username."""
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


@pytest.fixture
def fake() -> Fake:
    return Fake(42)


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_SAFE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AI_SAFE_WORKSPACE_BASE", str(tmp_path / "workspaces"))
    for var in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "AI_SAFE_AGENT", "CURSOR_AGENT", "AI_SAFE_MAPPING_PASSPHRASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("COLUMNS", "200")
    yield


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return out.stdout.decode()


def write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


@pytest.fixture
def make_repo(tmp_path):
    def _make(files: dict[str, str] | None = None, *, commit: bool = True, name: str = "repo") -> Path:
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        write(repo, files or {"README.md": "# demo\n"})
        if commit:
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "initial")
        return repo

    return _make


def builtin_config(**overrides) -> AISafeConfig:
    cfg = AISafeConfig(scanner=ScannerConfig(engine="builtin"))
    for k, v in overrides.items():
        section, field = k.split("__")
        setattr(getattr(cfg, section), field, v)
    return cfg


@pytest.fixture
def gitleaks_bin():
    exe = find_gitleaks(None) or (PROJECT_ROOT / "tools" / "bin" / "gitleaks")
    if not Path(exe).exists():
        pytest.skip("gitleaks binary not available")
    os.environ["AI_SAFE_GITLEAKS"] = str(exe)
    yield Path(exe)
    os.environ.pop("AI_SAFE_GITLEAKS", None)


@dataclass
class Prepared:
    repo: Path
    cfg: AISafeConfig
    store: SessionStore
    salt: bytes
    scanner: Scanner
    scan: object
    session: object
    result: object
    verification: object

    @property
    def ws(self) -> Path:
        return self.session.workspace_path


def prepare(repo: Path, cfg: AISafeConfig | None = None, passphrase: str | None = None) -> Prepared:
    """Programmatic equivalent of `ai-safe start` (without deleting on failure)."""
    cfg = cfg or builtin_config()
    store = SessionStore(state_root(cfg))
    salt = store.repo_salt(repo)
    scanner = Scanner(cfg, salt)
    scan = scanner.scan(repo)
    session = store.create(scan.root, cfg)
    result = Sanitizer(cfg, scanner, salt).run(scan, session, passphrase=passphrase)
    cmap = CredentialMap.load(session.state_path)
    vr = verify_workspace(session.workspace_path, cfg, scanner, original_repo=scan.root, fingerprints=cmap.fingerprints())
    if vr.passed:  # mirror `ai-safe start`
        session.status, session.verified_tree_hash = "verified", vr.tree_hash
        session.save()
    return Prepared(repo, cfg, store, salt, scanner, scan, session, result, vr)


def tree_snapshot(root: Path) -> dict[str, bytes]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out[str(p.relative_to(root))] = p.read_bytes()
    return out


def all_text(root: Path) -> str:
    chunks = []
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            chunks.append(p.read_bytes().decode("utf-8", "replace"))
    return "\n".join(chunks)
