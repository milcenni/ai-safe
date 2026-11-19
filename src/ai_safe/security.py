"""Low-level security primitives used by every other module.

Responsibilities:
* secure temporary directories and private files (0700 / 0600, O_NOFOLLOW)
* path validation: traversal, absolute paths, symlink components
* secret redaction for anything that is printed or logged
* keyed fingerprints (HMAC) so secrets can be matched without being stored
* hardened subprocess execution (no shell, no Git hooks, no external diff)
* secure cleanup
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath

PLACEHOLDER_PREFIX = "AI_SAFE_SECRET_"
PLACEHOLDER_RE = re.compile(r"\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}")
PLACEHOLDER_NAME_RE = re.compile(r"AI_SAFE_SECRET_[A-Z0-9_]+")
_PLACEHOLDER_VALUE_RE = re.compile(r"\$?\{?AI_SAFE_SECRET_[A-Z0-9_]+\}?")

MARKER_FILE = ".ai-safe-workspace.json"
WORKSPACE_PREFIX = "ai-safe-ws-"
_SAFE_PREFIX_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class SecurityError(Exception):
    """Raised when an operation would violate a security control.

    Messages must never contain secret values.
    """


class CommandError(SecurityError):
    pass


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


class Redactor:
    """Replaces known secret values in text with ``[REDACTED]``.

    The redactor is a last line of defence: code is written so that secrets are
    never formatted into messages in the first place.
    """

    MIN_LEN = 4

    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._pattern: re.Pattern[str] | None = None
        self._lock = threading.Lock()

    def add(self, secret: str | None) -> None:
        if not secret or len(secret) < self.MIN_LEN:
            return
        with self._lock:
            if secret in self._secrets:
                return
            self._secrets.add(secret)
            # Also redact individual lines of multi-line secrets (private keys).
            for part in secret.splitlines():
                part = part.strip()
                if len(part) >= 16:
                    self._secrets.add(part)
            self._pattern = None

    def add_many(self, secrets: Iterable[str]) -> None:
        for s in secrets:
            self.add(s)

    def clear(self) -> None:
        with self._lock:
            self._secrets.clear()
            self._pattern = None

    def __len__(self) -> int:
        return len(self._secrets)

    def redact(self, text: str) -> str:
        if not text or not self._secrets:
            return text
        with self._lock:
            if self._pattern is None:
                ordered = sorted(self._secrets, key=len, reverse=True)
                self._pattern = re.compile("|".join(re.escape(s) for s in ordered))
            pattern = self._pattern
        return pattern.sub("[REDACTED]", text)


REDACTOR = Redactor()


class RedactingFilter(logging.Filter):
    def __init__(self, redactor: Redactor = REDACTOR) -> None:
        super().__init__()
        self.redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - trivial
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        record.msg = self.redactor.redact(msg)
        record.args = ()
        return True


class RedactingStream:
    """File-like wrapper that redacts everything written through it."""

    def __init__(self, stream, redactor: Redactor = REDACTOR) -> None:
        self._stream = stream
        self._redactor = redactor

    def write(self, s: str) -> int:
        return self._stream.write(self._redactor.redact(s))

    def flush(self) -> None:
        self._stream.flush()

    def isatty(self) -> bool:
        try:
            return self._stream.isatty()
        except Exception:
            return False

    def fileno(self) -> int:
        return self._stream.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._stream, "encoding", "utf-8")


def is_placeholder_value(value: str) -> bool:
    v = value.strip().strip("\"'`")
    return bool(_PLACEHOLDER_VALUE_RE.fullmatch(v))


def contains_placeholder(text: str) -> bool:
    return PLACEHOLDER_NAME_RE.search(text) is not None


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


def hmac_fingerprint(secret: str, salt: bytes) -> str:
    """Keyed fingerprint. Without the salt (stored outside the AI workspace)
    a fingerprint cannot be used to brute-force short passwords offline."""
    return hmac.new(salt, secret.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:24]


def keyed_digest(data: bytes, salt: bytes) -> str:
    return hmac.new(salt, data, hashlib.sha256).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------


def secure_mkdtemp(prefix: str, base: Path | None = None) -> Path:
    """Create a private (0700) directory with an unpredictable name.

    The prefix is validated so that credentials can never end up in a
    temporary filename."""
    if not _SAFE_PREFIX_RE.match(prefix):
        raise SecurityError("unsafe temporary directory prefix")
    if base is not None:
        base = Path(base)
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        if base.is_symlink() or not base.is_dir():
            raise SecurityError("workspace base must be a real directory")
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base) if base else None))
    os.chmod(path, 0o700)
    return path


def ensure_private_dir(path: Path, *, create: bool = True, strict_mode: bool = True) -> Path:
    """Ensure ``path`` is a real directory owned by the current user.

    With ``strict_mode`` the permissions are forced to 0700."""
    path = Path(path)
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise SecurityError(f"refusing to use symlinked directory: {path}")
    if not stat.S_ISDIR(st.st_mode):
        raise SecurityError(f"not a directory: {path}")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SecurityError(f"directory is not owned by the current user: {path}")
    if strict_mode and stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def write_private_file(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    """Atomically write a file with restrictive permissions, never following
    a symlink at the destination."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if path.is_symlink():
        raise SecurityError(f"refusing to write through symlink: {path}")
    fd, tmp = tempfile.mkstemp(prefix=".ai-safe-tmp-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Atomic replacement used during integration (keeps ``mode``)."""
    write_private_file(path, data, mode=mode)
    os.chmod(path, mode)


def safe_relpath(rel: str | PurePosixPath) -> PurePosixPath:
    """Validate a repository-relative path.

    Rejects absolute paths, ``..`` components, NUL bytes, backslashes, control
    characters and Windows drive prefixes."""
    s = str(rel)
    if not s or s in (".", "./"):
        raise SecurityError("empty path")
    if "\x00" in s or any(ord(c) < 32 for c in s):
        raise SecurityError("path contains control characters")
    if "\\" in s:
        raise SecurityError("path contains a backslash")
    if s.startswith("/") or re.match(r"^[A-Za-z]:", s):
        raise SecurityError("absolute path not allowed")
    p = PurePosixPath(s)
    if any(part == ".." for part in p.parts):
        raise SecurityError("path traversal detected")
    parts = [part for part in p.parts if part not in ("", ".")]
    if not parts:
        raise SecurityError("empty path")
    return PurePosixPath(*parts)


def is_git_metadata_path(rel: str | PurePosixPath) -> bool:
    return any(part.casefold() == ".git" for part in PurePosixPath(str(rel)).parts)


def is_within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(root)))
        return True
    except ValueError:
        return False


def safe_join(root: Path, rel: str | PurePosixPath) -> Path:
    """Join ``rel`` onto ``root`` refusing traversal and symlinked components.

    The final component may or may not exist; if it exists it must not be a
    symlink. Every existing intermediate component must be a real directory."""
    relp = safe_relpath(rel)
    root = Path(os.path.realpath(root))
    current = root
    for i, part in enumerate(relp.parts):
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(st.st_mode):
            raise SecurityError(f"symlink in path: {relp}")
        if i < len(relp.parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise SecurityError(f"non-directory component in path: {relp}")
    target = root.joinpath(*relp.parts)
    if not is_within(target.parent, root):
        raise SecurityError(f"path escapes root: {relp}")
    return target


def symlink_escapes(link: Path, root: Path) -> bool:
    try:
        target = os.readlink(link)
    except OSError:
        return True
    resolved = os.path.realpath(os.path.join(os.path.dirname(link), target))
    return not is_within(Path(resolved), root)


def safe_file_mode(mode: int, preserve: bool = True) -> int:
    """Strip setuid/setgid/sticky and group/other write; keep owner rw."""
    if not preserve:
        return 0o644
    m = stat.S_IMODE(mode) & 0o755
    return m | 0o600


def _shred_file(path: Path) -> None:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return
        size = st.st_size
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            chunk = b"\x00" * 65536
            remaining = size
            while remaining > 0:
                n = os.write(fd, chunk[: min(remaining, len(chunk))])
                remaining -= n
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def secure_remove_file(path: Path, shred: bool = True) -> None:
    path = Path(path)
    if not os.path.lexists(path):
        return
    if shred and not path.is_symlink():
        _shred_file(path)
    os.unlink(path)


def secure_remove_tree(path: Path, shred: bool = False) -> None:
    """Remove a directory tree without following symlinks.

    ``shred`` overwrites regular files with zeros before unlinking. On SSDs and
    copy-on-write filesystems this is best effort only (documented limitation)."""
    path = Path(path)
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        secure_remove_file(path, shred=shred)
        return
    for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        # make sure we can descend / delete even if the AI removed permissions
        try:
            os.chmod(dirpath, 0o700)
        except OSError:
            pass
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                os.unlink(full)
                dirnames.remove(d)
        if shred:
            for f in filenames:
                full = Path(dirpath) / f
                if not full.is_symlink():
                    try:
                        os.chmod(full, 0o600)
                    except OSError:
                        pass
                    _shred_file(full)
    shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Subprocesses
# ---------------------------------------------------------------------------

GIT_SAFE_CONFIG = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.pager=cat",
    "-c", "core.quotePath=false",
    "-c", "color.ui=false",
    "-c", "diff.external=",
    "-c", "protocol.allow=never",
]

_GIT_ENV_DROP = {
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_EXTERNAL_DIFF", "GIT_SSH",
    "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXEC_PATH", "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_PAGER", "GIT_EDITOR",
    "GIT_TRACE", "GIT_TRACE_PACKET", "GIT_CEILING_DIRECTORIES", "GIT_NAMESPACE",
}


def safe_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP and not k.startswith("GIT_CONFIG_KEY_") and not k.startswith("GIT_CONFIG_VALUE_")}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if extra:
        env.update(extra)
    return env


def run_command(
    args: Sequence[str],
    cwd: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    timeout: int = 600,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command without a shell. Error messages are redacted/truncated."""
    try:
        proc = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else safe_env(),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"executable not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"command timed out: {Path(args[0]).name}") from exc
    if check and proc.returncode != 0:
        err = REDACTOR.redact(proc.stderr.decode("utf-8", "replace"))[-800:]
        raise CommandError(f"{Path(args[0]).name} failed (exit {proc.returncode}): {err.strip()}")
    return proc


AGENT_ENV_VARS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "AI_SAFE_AGENT", "CURSOR_AGENT")


def detect_ai_agent_env() -> str | None:
    """Return the name of an env var indicating we run inside an AI agent."""
    for name in AGENT_ENV_VARS:
        if os.environ.get(name):
            return name
    return None


def read_nofollow(path: Path) -> bytes:
    """Read a regular file without following a symlink at the final component.

    Protects against a file being swapped for a symlink between inspection
    and reading (TOCTOU) in attacker-controlled directories."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityError(f"not a regular file: {Path(path).name}")
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def is_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


# ---------------------------------------------------------------------------
# Race-free directory walking for attacker-controlled trees
# ---------------------------------------------------------------------------


class WalkEntry:
    __slots__ = ("rel", "kind", "st", "data", "link_target", "children")

    def __init__(self, rel: str, kind: str, st: os.stat_result, data: bytes | None = None,
                 link_target: str | None = None, children: tuple[str, ...] = ()) -> None:
        self.rel = rel
        self.kind = kind  # file | dir | symlink | special | unreadable
        self.st = st
        self.data = data
        self.link_target = link_target
        self.children = children


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def walk_nofollow(root: Path, *, read_files: bool = True, max_bytes: int | None = None) -> list[WalkEntry]:
    """Walk ``root`` holding a directory fd for every level (openat-style).

    Every component is opened relative to its parent's fd with O_NOFOLLOW, so
    swapping a directory for a symlink at any point during the walk cannot
    redirect reads outside ``root``. File contents are captured during the
    walk; callers must use ``entry.data`` instead of re-reading by path."""
    out: list[WalkEntry] = []
    root_fd = os.open(root, _DIR_FLAGS)

    def rec(dfd: int, prefix: str) -> tuple[str, ...]:
        with os.scandir(dfd) as it:
            names = sorted(e.name for e in it)
        for name in names:
            rel = prefix + name
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                try:
                    target = os.readlink(name, dir_fd=dfd)
                except OSError:
                    target = None
                out.append(WalkEntry(rel, "symlink", st, link_target=target))
            elif stat.S_ISDIR(mode):
                try:
                    cfd = os.open(name, _DIR_FLAGS, dir_fd=dfd)
                except OSError:
                    out.append(WalkEntry(rel, "unreadable", st))
                    continue
                entry = WalkEntry(rel, "dir", st)
                out.append(entry)
                try:
                    if (os.fstat(cfd).st_dev, os.fstat(cfd).st_ino) != (st.st_dev, st.st_ino):
                        entry.kind = "unreadable"
                        continue
                    entry.children = rec(cfd, rel + "/")
                finally:
                    os.close(cfd)
            elif stat.S_ISREG(mode):
                data = None
                if read_files and (max_bytes is None or st.st_size <= max_bytes):
                    try:
                        fd = os.open(name, _FILE_FLAGS, dir_fd=dfd)
                    except OSError:
                        out.append(WalkEntry(rel, "unreadable", st))
                        continue
                    try:
                        fst = os.fstat(fd)
                        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                            out.append(WalkEntry(rel, "unreadable", st))
                            continue
                        chunks = []
                        while True:
                            b = os.read(fd, 1 << 20)
                            if not b:
                                break
                            chunks.append(b)
                        data = b"".join(chunks)
                        st = fst
                    finally:
                        os.close(fd)
                out.append(WalkEntry(rel, "file", st, data=data))
            else:
                out.append(WalkEntry(rel, "special", st))
        return tuple(names)

    try:
        rec(root_fd, "")
    finally:
        os.close(root_fd)
    return out


def symlink_target_escapes(rel: str, target: str | None, root: Path) -> bool:
    if target is None:
        return True
    base = os.path.join(os.path.realpath(root), os.path.dirname(rel))
    resolved = os.path.realpath(os.path.join(base, target))
    return not is_within(Path(resolved), root)


# ---------------------------------------------------------------------------
# Terminal-safe display of untrusted text
# ---------------------------------------------------------------------------

_BIDI = "‎‏‪‫‬‭‮⁦⁧⁨⁩؜"
_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")
HIDDEN_CHARS_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f" + _BIDI + "]")


def safe_display(text: str) -> str:
    """Make untrusted text safe for a terminal: escape C0/C1 control
    characters (ANSI escape sequences) and bidi overrides."""
    return _CTRL_RE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text)
