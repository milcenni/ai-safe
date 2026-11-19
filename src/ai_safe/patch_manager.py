"""Change extraction and patch mapping.

AI changes are the difference between the pristine snapshot (kept in the
state directory, out of the AI's reach) and the workspace.

Mapping a hunk back onto the original file:

    snapshot (sanitized) --SequenceMatcher--> original (real credentials)

Lines that are equal in both are "plain" lines; lines that differ are
"credential lines" (they contained a redacted secret). An AI hunk is applied
to the original by translating its snapshot range through this alignment.

* A hunk that only touches plain lines applies cleanly.
* A hunk that rewrites credential lines **without** placeholders in its new
  text (e.g. hardcoded value replaced by an env lookup) applies, with a
  warning: the hardcoded credential is removed from the original.
* A hunk whose new text still contains a placeholder while touching a
  credential line is a **conflict**: applying it would require writing the
  real credential back into an AI-generated line, which ai-safe never does.
"""

from __future__ import annotations

import difflib
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ai_safe.security import contains_placeholder, is_binary, read_nofollow, sha256_bytes, walk_nofollow


@dataclass
class EntryInfo:
    kind: str  # file | symlink | dir | special
    mode: int = 0
    sha256: str | None = None
    size: int = 0
    nlink: int = 1
    data: bytes | None = field(default=None, repr=False)  # captured once, race-free


def tree_index(root: Path) -> dict[str, EntryInfo]:
    """Index of every entry under ``root``.

    Uses :func:`walk_nofollow`, so symlinks are never followed at any path
    component and file contents are captured during the walk. Consumers must
    use ``EntryInfo.data`` rather than re-reading files by path."""
    out: dict[str, EntryInfo] = {}
    for e in walk_nofollow(Path(root)):
        if e.kind == "dir":
            continue
        if e.kind == "symlink":
            out[e.rel] = EntryInfo("symlink")
        elif e.kind == "file" and e.data is not None:
            out[e.rel] = EntryInfo("file", stat.S_IMODE(e.st.st_mode), sha256_bytes(e.data), e.st.st_size, e.st.st_nlink, e.data)
        else:
            out[e.rel] = EntryInfo("special")
    return out


@dataclass
class FileChange:
    path: str
    kind: str  # added | modified | deleted | type_changed | mode_changed
    old: EntryInfo | None = None
    new: EntryInfo | None = None

    @property
    def is_symlink(self) -> bool:
        return bool(self.new and self.new.kind == "symlink")


def collect_changes(snapshot: Path, workspace: Path) -> list[FileChange]:
    a = tree_index(snapshot)
    b = tree_index(workspace)
    changes: list[FileChange] = []
    for path in sorted(set(a) | set(b)):
        old, new = a.get(path), b.get(path)
        if old is None:
            changes.append(FileChange(path, "added", None, new))
        elif new is None:
            changes.append(FileChange(path, "deleted", old, None))
        elif old.kind != new.kind:
            changes.append(FileChange(path, "type_changed", old, new))
        elif old.kind == "file" and old.sha256 != new.sha256:
            changes.append(FileChange(path, "modified", old, new))
        elif old.kind == "file" and (old.mode & 0o111) != (new.mode & 0o111):
            changes.append(FileChange(path, "mode_changed", old, new))
    return changes


@dataclass
class Hunk:
    i1: int  # snapshot range [i1, i2)
    i2: int
    new_lines: list[str]
    old_lines: list[str]


def compute_hunks(old_text: str, new_text: str) -> list[Hunk]:
    a = old_text.splitlines(keepends=True)
    b = new_text.splitlines(keepends=True)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [Hunk(i1, i2, b[j1:j2], a[i1:i2]) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]


@dataclass
class MappedResult:
    text: str | None
    conflicts: list[tuple[int, str]] = field(default_factory=list)  # (snapshot line, message)
    warnings: list[tuple[int, str]] = field(default_factory=list)
    credential_lines_original: set[int] = field(default_factory=set)  # 0-based original line indexes


class _Alignment:
    def __init__(self, snap: list[str], orig: list[str]) -> None:
        self.snap = snap
        self.orig = orig
        self.ops = []
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, snap, orig, autojunk=False).get_opcodes():
            if tag == "replace" and (i2 - i1) == (j2 - j1):
                # single-line redactions keep line counts: map one-to-one
                self.ops.extend(("replace", i1 + k, i1 + k + 1, j1 + k, j1 + k + 1) for k in range(i2 - i1))
            else:
                self.ops.append((tag, i1, i2, j1, j2))
        self.secret_snapshot_lines: set[int] = set()
        self.secret_original_lines: set[int] = set()
        for tag, i1, i2, j1, j2 in self.ops:
            if tag != "equal":
                self.secret_snapshot_lines.update(range(i1, i2))
                self.secret_original_lines.update(range(j1, j2))

    def boundary(self, i: int) -> int | None:
        """Original index corresponding to snapshot boundary ``i``.

        Defined when ``i`` falls on an equal block or at the start of a
        non-equal block; ``None`` if ``i`` splits a credential region."""
        if i >= len(self.snap):
            return len(self.orig)
        for tag, i1, i2, j1, j2 in self.ops:
            if i1 <= i < i2 or (i1 == i2 == i):
                if tag == "equal":
                    return j1 + (i - i1)
                return j1 if i == i1 else None
        return None


def map_to_original(snapshot_text: str, workspace_text: str, original_text: str, path: str) -> MappedResult:
    snap = snapshot_text.splitlines(keepends=True)
    orig = original_text.splitlines(keepends=True)
    align = _Alignment(snap, orig)
    hunks = compute_hunks(snapshot_text, workspace_text)
    result = MappedResult(text=None, credential_lines_original=set(align.secret_original_lines))
    edits: list[tuple[int, int, list[str]]] = []
    for h in hunks:
        o1 = align.boundary(h.i1)
        o2 = align.boundary(h.i2) if h.i2 > h.i1 else o1
        touches_secret = any(i in align.secret_snapshot_lines for i in range(h.i1, h.i2))
        new_has_placeholder = any(contains_placeholder(line) for line in h.new_lines)
        line_no = h.i1 + 1
        if o1 is None or o2 is None or o2 < o1:
            result.conflicts.append((line_no, "change splits a multi-line region containing a sanitized credential - apply manually"))
            continue
        if touches_secret and new_has_placeholder:
            result.conflicts.append((
                line_no,
                "AI modified a line containing a sanitized credential and kept the placeholder; "
                "ai-safe will not restore credentials into AI-generated lines - apply this change manually",
            ))
            continue
        if touches_secret:
            result.warnings.append((
                line_no,
                "hardcoded credential removed by AI change - make sure the value is supplied via environment/secret manager",
            ))
        edits.append((o1, o2, h.new_lines))
    if result.conflicts:
        return result
    out = list(orig)
    for o1, o2, new_lines in sorted(edits, key=lambda e: e[0], reverse=True):
        out[o1:o2] = new_lines
    result.text = "".join(out)
    return result


def unified_diff_masked(path: str, old_text: str, new_text: str, masked_old_lines: set[int], context: int = 3) -> str:
    """Unified diff where original credential lines are masked."""
    old = old_text.splitlines(keepends=True)
    new = new_text.splitlines(keepends=True)
    mask = "<line containing a credential - hidden by ai-safe>\n"
    old_m = [mask if i in masked_old_lines else line for i, line in enumerate(old)]
    # Unchanged credential lines also appear in ``new``; mask them identically.
    masked_contents = {old[i] for i in masked_old_lines if i < len(old)}
    new_m = [mask if line in masked_contents else line for line in new]
    return "".join(difflib.unified_diff(old_m, new_m, fromfile=f"a/{path}", tofile=f"b/{path}", n=context))


def read_text_or_none(path: Path) -> str | None:
    data = read_nofollow(Path(path))
    if is_binary(data):
        return None
    return data.decode("utf-8")
