"""Session state, AI workspace creation, Claude Code integration and cleanup.

Layout::

    <state root>/                    0700  (default ~/.local/state/ai-safe)
      repos/<repo-id>/salt           0600  per-repository HMAC salt
      sessions/<id>/                 0700
        session.json                 paths + status (never secrets)
        manifest.json                sanitization manifest (never secrets)
        credential-map.json          placeholder metadata (never secrets)
        credential-secrets.enc       optional, encrypted
        snapshot/                    pristine copy of the sanitized workspace
        reports/                     scan/verify/review/integration reports
        patches/                     redacted record of integrated patches

    <workspace base>/ai-safe-ws-XXXX/  0700  the ONLY directory given to the AI
      .ai-safe-workspace.json        marker: session id only (no paths)
      .claude/skills/...             generated skills
      .claude/settings.json          generated permission deny rules

The workspace never contains the original ``.git`` directory or any path to
the original repository.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
import shutil
import stat
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path

from ai_safe.config import AISafeConfig
from ai_safe.security import (
    MARKER_FILE,
    WORKSPACE_PREFIX,
    SecurityError,
    ensure_private_dir,
    is_within,
    secure_mkdtemp,
    secure_remove_tree,
    sha256_bytes,
    write_private_file,
)

STATE_ENV = "AI_SAFE_STATE_DIR"
WORKSPACE_BASE_ENV = "AI_SAFE_WORKSPACE_BASE"
SKILL_NAMES = (
    "ai-safe",
    "ai-safe-scan",
    "ai-safe-sanitize",
    "ai-safe-review",
    "ai-safe-integrate",
    "ai-safe-security-audit",
)
HISTORY_SUMMARY_FILE = "AI_SAFE_HISTORY.md"
PLACEHOLDERS_FILE = "AI_SAFE_PLACEHOLDERS.md"
CLAUDE_SETTINGS = ".claude/settings.json"


def generated_paths() -> set[str]:
    paths = {MARKER_FILE, CLAUDE_SETTINGS, HISTORY_SUMMARY_FILE, PLACEHOLDERS_FILE}
    paths |= {f".claude/skills/{n}/SKILL.md" for n in SKILL_NAMES}
    return paths


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def state_root(cfg: AISafeConfig | None = None) -> Path:
    if os.environ.get(STATE_ENV):
        root = Path(os.environ[STATE_ENV]).expanduser()
    elif cfg is not None and cfg.workspace.state_dir:
        root = Path(cfg.workspace.state_dir).expanduser()
    else:
        xdg = os.environ.get("XDG_STATE_HOME")
        root = (Path(xdg) if xdg else Path.home() / ".local" / "state") / "ai-safe"
    root = root.resolve()
    ensure_private_dir(root)
    return root


def workspace_base(cfg: AISafeConfig) -> Path | None:
    if os.environ.get(WORKSPACE_BASE_ENV):
        return Path(os.environ[WORKSPACE_BASE_ENV]).expanduser().resolve()
    if cfg.workspace.base_dir:
        return Path(cfg.workspace.base_dir).expanduser().resolve()
    return None


@dataclass
class Session:
    id: str
    repo: str
    workspace: str
    state_dir: str
    created_at: str
    status: str = "created"  # created | sanitized | verified | failed | integrated
    verified_tree_hash: str | None = None
    history_only_secrets: int = 0

    @property
    def repo_path(self) -> Path:
        return Path(self.repo)

    @property
    def workspace_path(self) -> Path:
        return Path(self.workspace)

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir)

    @property
    def snapshot_dir(self) -> Path:
        return self.state_path / "snapshot"

    @property
    def manifest_path(self) -> Path:
        return self.state_path / "manifest.json"

    @property
    def reports_dir(self) -> Path:
        d = self.state_path / "reports"
        ensure_private_dir(d)
        return d

    @property
    def patches_dir(self) -> Path:
        d = self.state_path / "patches"
        ensure_private_dir(d)
        return d

    def save(self) -> None:
        write_private_file(self.state_path / "session.json", json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, state_dir: Path) -> "Session":
        data = json.loads((Path(state_dir) / "session.json").read_text())
        return cls(**data)

    def load_manifest(self) -> dict:
        if not self.manifest_path.exists():
            raise SecurityError("session has no sanitization manifest")
        return json.loads(self.manifest_path.read_text())


class SessionStore:
    def __init__(self, root: Path) -> None:
        self.root = ensure_private_dir(Path(root))
        self.sessions_dir = ensure_private_dir(self.root / "sessions")
        self.repos_dir = ensure_private_dir(self.root / "repos")

    # -- salts --------------------------------------------------------------

    def repo_salt(self, repo: Path) -> bytes:
        rid = hashlib.sha256(str(Path(repo).resolve()).encode()).hexdigest()[:20]
        d = ensure_private_dir(self.repos_dir / rid)
        p = d / "salt"
        if p.exists():
            data = p.read_bytes()
            if len(data) == 32:
                return data
        salt = secrets.token_bytes(32)
        write_private_file(p, salt)
        return salt

    # -- lifecycle ------------------------------------------------------------

    def create(self, repo: Path, cfg: AISafeConfig) -> Session:
        repo = Path(repo).resolve()
        base = workspace_base(cfg)
        if is_within(self.root, repo):
            raise SecurityError("the ai-safe state directory must not be inside the repository")
        if base is not None and is_within(base, repo):
            raise SecurityError("the workspace base directory must not be inside the repository")
        sid = secrets.token_hex(8)
        state_dir = ensure_private_dir(self.sessions_dir / sid)
        ws = secure_mkdtemp(WORKSPACE_PREFIX, base)
        try:
            if is_within(ws, repo) or is_within(repo, ws):
                raise SecurityError("AI workspace must be outside the original repository")
            if is_within(ws, self.root) or is_within(self.root, ws):
                raise SecurityError("AI workspace must not overlap the ai-safe state directory")
        except SecurityError:
            secure_remove_tree(ws)
            secure_remove_tree(state_dir)
            raise
        session = Session(id=sid, repo=str(repo), workspace=str(ws), state_dir=str(state_dir), created_at=_now())
        session.save()
        write_marker(ws, sid)
        return session

    def get(self, sid: str) -> Session:
        if not sid or not all(c in "0123456789abcdef" for c in sid):
            raise SecurityError("invalid session id")
        d = self.sessions_dir / sid
        if not (d / "session.json").exists():
            raise SecurityError(f"unknown session: {sid}")
        return Session.load(d)

    def list(self) -> list[Session]:
        out = []
        for d in sorted(self.sessions_dir.iterdir()):
            if (d / "session.json").exists():
                try:
                    out.append(Session.load(d))
                except Exception:
                    continue
        return sorted(out, key=lambda s: s.created_at)

    def latest_for_repo(self, repo: Path) -> Session | None:
        repo = str(Path(repo).resolve())
        matching = [s for s in self.list() if s.repo == repo]
        return matching[-1] if matching else None

    def find_for_workspace(self, path: Path) -> Session | None:
        p = Path(path).resolve()
        for candidate in (p, *p.parents):
            marker = candidate / MARKER_FILE
            if marker.is_file() and not marker.is_symlink():
                try:
                    sid = json.loads(marker.read_text()).get("session_id", "")
                    session = self.get(sid)
                except Exception:
                    raise SecurityError("workspace marker is invalid or tampered") from None
                if Path(session.workspace).resolve() != candidate:
                    raise SecurityError("workspace marker does not match the recorded session")
                return session
        return None

    def resolve(self, session_id: str | None, cwd: Path) -> Session:
        if session_id:
            return self.get(session_id)
        s = self.find_for_workspace(cwd)
        if s:
            return s
        try:
            from ai_safe import git_history as gh

            root = gh.repo_root(cwd) if gh.is_git_repo(cwd) else Path(cwd).resolve()
        except Exception:
            root = Path(cwd).resolve()
        s = self.latest_for_repo(root)
        if s is None:
            raise SecurityError("no ai-safe session found for this directory (run `ai-safe start` first, or pass --session)")
        return s

    def cleanup(self, session: Session) -> list[str]:
        """Securely remove the workspace and the session state."""
        removed = []
        ws = Path(session.workspace)
        repo = Path(session.repo)
        if os.path.lexists(ws):
            if not ws.name.startswith(WORKSPACE_PREFIX):
                raise SecurityError("refusing to delete a directory that is not an ai-safe workspace")
            if is_within(repo, ws) or is_within(ws, repo):
                raise SecurityError("refusing to delete: workspace overlaps the original repository")
            marker = ws / MARKER_FILE
            if marker.is_file():
                try:
                    sid = json.loads(marker.read_text()).get("session_id")
                except Exception:
                    sid = None
                if sid != session.id:
                    raise SecurityError("refusing to delete: workspace marker does not match the session")
            secure_remove_tree(ws, shred=False)
            removed.append(str(ws))
        state = Path(session.state_dir)
        if not is_within(state, self.sessions_dir):
            raise SecurityError("refusing to delete state outside the ai-safe state directory")
        if state.exists():
            secure_remove_tree(state, shred=True)
            removed.append(str(state))
        return removed


# ---------------------------------------------------------------------------
# Workspace contents
# ---------------------------------------------------------------------------


def write_marker(ws: Path, sid: str) -> None:
    doc = {"tool": "ai-safe", "session_id": sid, "note": "AI-safe sanitized workspace. Contains placeholders, not real credentials."}
    write_private_file(Path(ws) / MARKER_FILE, json.dumps(doc, indent=2), mode=0o644)


def skill_template(name: str) -> str:
    if name not in SKILL_NAMES:
        raise SecurityError(f"unknown skill: {name}")
    return (resources.files("ai_safe") / "skill_templates" / name / "SKILL.md").read_text(encoding="utf-8")


def install_skills(dest_root: Path) -> list[Path]:
    """Write all skills to ``<dest_root>/.claude/skills/<name>/SKILL.md``."""
    written = []
    for name in SKILL_NAMES:
        d = Path(dest_root) / ".claude" / "skills" / name
        d.mkdir(parents=True, exist_ok=True)
        p = d / "SKILL.md"
        write_private_file(p, skill_template(name), mode=0o644)
        written.append(p)
    return written


def claude_settings(state_root_path: Path) -> dict:
    deny = [
        "Read(./.env)", "Read(./.env.*)", "Read(**/.env)", "Read(**/.env.*)",
        "Edit(./.env)", "Edit(./.env.*)", "Edit(**/.env)", "Edit(**/.env.*)",
        "Write(./.env)", "Write(./.env.*)", "Write(**/.env)", "Write(**/.env.*)",
        "Edit(./.ai-safe-workspace.json)", "Write(./.ai-safe-workspace.json)",
        "Bash(git push:*)", "Bash(ai-safe integrate:*)", "Bash(ai-safe cleanup:*)",
    ]
    home = Path.home().resolve()
    try:
        rel = state_root_path.resolve().relative_to(home)
        deny += [f"Read(~/{rel}/**)", f"Edit(~/{rel}/**)"]
    except ValueError:
        deny += [f"Read(/{state_root_path}/**)", f"Edit(/{state_root_path}/**)"]
    return {
        "_comment": "Generated by ai-safe. Defence in depth only - isolation must be enforced by the OS/sandbox. The original repository path is intentionally not listed.",
        "permissions": {"deny": deny},
    }


def install_claude_integration(ws: Path, state_root_path: Path, cfg: AISafeConfig) -> None:
    if cfg.workspace.install_skills:
        install_skills(ws)
    if cfg.workspace.generate_claude_settings:
        p = Path(ws) / CLAUDE_SETTINGS
        p.parent.mkdir(parents=True, exist_ok=True)
        write_private_file(p, json.dumps(claude_settings(state_root_path), indent=2), mode=0o644)


# ---------------------------------------------------------------------------
# Snapshot / tree hashing
# ---------------------------------------------------------------------------


def take_snapshot(ws: Path, snapshot: Path) -> None:
    if snapshot.exists():
        secure_remove_tree(snapshot)
    shutil.copytree(ws, snapshot, symlinks=True)
    os.chmod(snapshot, 0o700)


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            h.update(rel.encode("utf-8", "surrogateescape") + b"\0")
            h.update(str(stat.S_IFMT(st.st_mode)).encode() + b"\0")
            if stat.S_ISREG(st.st_mode):
                h.update(oct(stat.S_IMODE(st.st_mode)).encode())
                with open(full, "rb") as fh:
                    h.update(sha256_bytes(fh.read()).encode())
            elif stat.S_ISLNK(st.st_mode):
                h.update(os.readlink(full).encode("utf-8", "surrogateescape"))
    return h.hexdigest()
