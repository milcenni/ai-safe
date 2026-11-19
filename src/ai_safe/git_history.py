"""Git repository access (read-only).

Every Git invocation disables hooks, fsmonitor, external diff drivers and
textconv filters (``security.GIT_SAFE_CONFIG`` + ``--no-ext-diff
--no-textconv``) so scanning never executes project-controlled code. ai-safe
never writes to the repository's ``.git`` directory and never rewrites history.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ai_safe.security import GIT_SAFE_CONFIG, CommandError, run_command, safe_env

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def git(repo: Path, *args: str, check: bool = True, timeout: int = 600) -> bytes:
    proc = run_command(["git", *GIT_SAFE_CONFIG, *args], cwd=repo, env=safe_env(), check=check, timeout=timeout)
    return proc.stdout


def is_git_repo(path: Path) -> bool:
    try:
        out = git(Path(path), "rev-parse", "--is-inside-work-tree", check=True, timeout=30)
        return out.strip() == b"true"
    except CommandError:
        return False


def repo_root(path: Path) -> Path:
    out = git(Path(path), "rev-parse", "--show-toplevel", timeout=30)
    return Path(out.decode().strip()).resolve()


def has_commits(repo: Path) -> bool:
    proc = run_command(["git", *GIT_SAFE_CONFIG, "rev-parse", "--verify", "-q", "HEAD"], cwd=repo, check=False, timeout=30)
    return proc.returncode == 0


def _split_z(data: bytes) -> list[str]:
    return [p.decode("utf-8", "surrogateescape") for p in data.split(b"\x00") if p]


def list_tracked(repo: Path) -> list[str]:
    return _split_z(git(repo, "ls-files", "-z", "--cached", "--full-name"))


def list_untracked(repo: Path) -> list[str]:
    return _split_z(git(repo, "ls-files", "-z", "--others", "--exclude-standard", "--full-name"))


def list_ignored(repo: Path) -> list[str]:
    """Ignored files and directories (directories end with '/')."""
    return _split_z(git(repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--full-name"))


def staged_files(repo: Path) -> list[str]:
    return _split_z(git(repo, "diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT"))


def unstaged_files(repo: Path) -> list[str]:
    return _split_z(git(repo, "diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT"))


@dataclass
class AddedChunk:
    """Contiguous block of added lines in a diff."""

    path: str
    start_line: int
    lines: list[str] = field(default_factory=list)
    commit: str | None = None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _unquote_path(p: str) -> str:
    if p.startswith('"') and p.endswith('"'):
        body = p[1:-1]
        try:
            return body.encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode("utf-8", "replace")
        except Exception:
            return body
    return p


def parse_added_chunks(diff: str) -> Iterator[AddedChunk]:
    """Parse ``git diff -U0`` / ``git log -p -U0`` output into added-line chunks.

    Commits are delimited by lines of the form ``\\x00commit <sha>``."""
    commit: str | None = None
    path: str | None = None
    new_line = 0
    chunk: AddedChunk | None = None
    for raw in diff.split("\n"):
        if raw.startswith("\x00commit "):
            if chunk:
                yield chunk
                chunk = None
            commit = raw.split(" ", 1)[1].strip()
            path = None
            continue
        if raw.startswith("diff --git "):
            if chunk:
                yield chunk
                chunk = None
            path = None
            continue
        if raw.startswith("+++ "):
            target = raw[4:]
            if target == "/dev/null":
                path = None
            else:
                target = _unquote_path(target)
                path = target[2:] if target.startswith("b/") else target
            continue
        if raw.startswith("--- "):
            continue
        m = _HUNK_RE.match(raw)
        if m:
            if chunk:
                yield chunk
                chunk = None
            new_line = int(m.group(1))
            continue
        if path is None:
            continue
        if raw.startswith("+"):
            if chunk is None:
                chunk = AddedChunk(path=path, start_line=new_line, commit=commit)
            chunk.lines.append(raw[1:])
            new_line += 1
        elif raw.startswith(" "):
            if chunk:
                yield chunk
                chunk = None
            new_line += 1
        else:
            if chunk:
                yield chunk
                chunk = None
    if chunk:
        yield chunk


_DIFF_FLAGS = ["--no-color", "--no-ext-diff", "--no-textconv", "-U0", "--no-renames"]


def staged_added_chunks(repo: Path) -> Iterator[AddedChunk]:
    out = git(repo, "diff", "--cached", *_DIFF_FLAGS).decode("utf-8", "replace")
    return parse_added_chunks(out)


def unstaged_added_chunks(repo: Path) -> Iterator[AddedChunk]:
    out = git(repo, "diff", *_DIFF_FLAGS).decode("utf-8", "replace")
    return parse_added_chunks(out)


def history_added_chunks(repo: Path, log_opts: str = "--all", timeout: int = 900) -> Iterator[AddedChunk]:
    """Every line ever added in any commit reachable from all refs.

    This covers secrets in deleted files and secrets removed from HEAD but
    retained in previous commits."""
    if not has_commits(repo):
        return iter(())
    args = ["log", *log_opts.split(), "-p", "--full-history", "--format=format:%x00commit %H",
            "--no-color", "--no-ext-diff", "--no-textconv", "-U0", "--no-renames"]
    out = git(repo, *args, timeout=timeout).decode("utf-8", "replace")
    return parse_added_chunks(out)


def commit_messages(repo: Path, log_opts: str = "--all") -> list[tuple[str, str]]:
    if not has_commits(repo):
        return []
    out = git(repo, "log", *log_opts.split(), "--format=format:%H%x00%B%x01").decode("utf-8", "replace")
    result = []
    for rec in out.split("\x01"):
        rec = rec.strip("\n")
        if not rec or "\x00" not in rec:
            continue
        sha, msg = rec.split("\x00", 1)
        result.append((sha.strip(), msg))
    return result


@dataclass
class HistoryStats:
    commits: int = 0
    branches: int = 0
    tags: int = 0


def history_stats(repo: Path) -> HistoryStats:
    if not has_commits(repo):
        return HistoryStats()
    commits = int(git(repo, "rev-list", "--all", "--count").decode().strip() or 0)
    refs = git(repo, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags").decode().split()
    return HistoryStats(
        commits=commits,
        branches=sum(1 for r in refs if r.startswith("refs/heads/")),
        tags=sum(1 for r in refs if r.startswith("refs/tags/")),
    )


@dataclass
class CommitSummary:
    short: str
    date: str
    subject: str
    files: list[tuple[str, str]]


def commit_summaries(repo: Path, max_commits: int = 200) -> list[CommitSummary]:
    """Commit metadata without diffs. Authors/emails are intentionally omitted."""
    if not has_commits(repo):
        return []
    out = git(
        repo, "log", "--all", "--date-order", f"--max-count={max_commits}", "--name-status",
        "--no-renames", "--format=format:%x01%h%x00%ad%x00%s", "--date=short",
    ).decode("utf-8", "replace")
    result: list[CommitSummary] = []
    for rec in out.split("\x01"):
        if not rec.strip():
            continue
        head, _, rest = rec.partition("\n")
        parts = head.split("\x00")
        if len(parts) != 3:
            continue
        files = []
        for line in rest.splitlines():
            if "\t" in line:
                status, path = line.split("\t", 1)
                files.append((status.strip(), path.strip()))
        result.append(CommitSummary(parts[0], parts[1], parts[2], files))
    return result
