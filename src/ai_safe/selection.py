"""Choosing which reviewed changes to integrate (`ai-safe integrate --only/--select`).

Review always runs on every change; selection only decides which planned changes are
written. See :meth:`ai_safe.review.ReviewReport.select` for the blocking rule.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ai_safe.models import Issue, Severity
from ai_safe.php_calls import is_php
from ai_safe.review import ReviewReport, is_always_blocking, is_tool_metadata

_GLOB_CHARS = set("*?[")


def _norm_pattern(pattern: str) -> str:
    pat = pattern.strip().replace("\\", "/")
    while pat.startswith("./"):
        pat = pat[2:]
    return pat


def _glob_parts_match(pat_parts: list[str], path_parts: list[str]) -> bool:
    """Segment-wise glob: ``*``/``?``/``[..]`` never cross ``/``; ``**`` spans any depth."""
    if not pat_parts:
        return not path_parts
    head, rest = pat_parts[0], pat_parts[1:]
    if head == "**":
        return any(_glob_parts_match(rest, path_parts[i:]) for i in range(len(path_parts) + 1))
    return bool(path_parts) and fnmatch.fnmatchcase(path_parts[0], head) and _glob_parts_match(rest, path_parts[1:])


def path_matches(pattern: str, path: str) -> bool:
    """``--only`` matching against a repo-relative path: an exact file, a directory prefix,
    or a glob. A glob that matches a directory selects everything below it."""
    pat = _norm_pattern(pattern)
    if not pat:
        return False
    if not _GLOB_CHARS & set(pat):
        pat = pat.rstrip("/")
        return bool(pat) and (path == pat or path.startswith(pat + "/"))
    pat_parts = [p for p in pat.rstrip("/").split("/") if p]
    parts = path.split("/")
    return any(_glob_parts_match(pat_parts, parts[:n]) for n in range(1, len(parts) + 1))


def match_only(patterns: tuple[str, ...] | list[str], paths: list[str]) -> tuple[set[str], list[str]]:
    """Paths matched by any pattern, and the patterns that matched nothing."""
    selected: set[str] = set()
    unmatched: list[str] = []
    for pat in patterns:
        hits = {p for p in paths if path_matches(pat, p)}
        if not hits:
            unmatched.append(pat)
        selected |= hits
    return selected, unmatched


# ---------------------------------------------------------------------------
# interactive picker
# ---------------------------------------------------------------------------


@dataclass
class Row:
    status: str  # modified | added | deleted | renamed | mode_changed | type_changed
    label: str  # "path" or "old -> new"
    paths: tuple[str, ...]
    review: str = ""
    selectable: bool = True
    notes: list[str] = field(default_factory=list)


def _skip_reason(report: ReviewReport, path: str) -> str | None:
    prefix = f"{path} ("
    for s in report.skipped:
        if s.startswith(prefix) and s.endswith(")"):
            return s[len(prefix):-1]
    return None


def _review_note(issues: list[Issue]) -> str:
    if not issues:
        return ""
    top = sorted(issues, key=lambda i: (i.code != "manual", -i.severity.rank, i.code))
    note = "manual (binary or mode-only)" if top[0].code == "manual" else f"{top[0].severity.value} {top[0].code}"
    return note + (f" +{len(top) - 1}" if len(top) > 1 else "")


def build_rows(report: ReviewReport) -> list[Row]:
    """One row per change; a rename pair is one row. Rows that review never integrates
    (manual binary/mode-only, tool metadata, Git metadata, excluded, ...) are not selectable."""
    planned = {p.path for p in report.candidates}
    by_path: dict[str, list[Issue]] = {}
    for i in report.issues:
        by_path.setdefault(i.path, []).append(i)
    kinds = {c.path: c.kind for c in report.changes}
    rename_of = {old: (old, new) for old, new in report.renames}
    rename_of.update({new: (old, new) for old, new in report.renames})
    rows: list[Row] = []
    done: set[str] = set()
    for ch in report.changes:
        if ch.path in done:
            continue
        pair = rename_of.get(ch.path)
        paths = pair if pair else (ch.path,)
        done.update(paths)
        issues = [i for p in paths for i in by_path.get(p, []) if i.severity is not Severity.INFO]
        # selectable: integratable, or blocked by its own issue (selecting it then blocks, as with --only)
        own_block = any(i.severity.blocking and not is_always_blocking(i) for i in issues)
        selectable = any(p in planned for p in paths) or own_block
        note = _review_note(issues)
        if not selectable:
            reasons = [r for r in (_skip_reason(report, p) for p in paths) if r]
            if any(is_tool_metadata(p) for p in paths) and not reasons:
                reasons = ["tool metadata - not integrated"]
            note = note or (reasons[0] if reasons else "not integrated")
        if pair:
            rows.append(Row("renamed", f"{pair[0]} -> {pair[1]}", pair, note, selectable))
        else:
            rows.append(Row(kinds[ch.path], ch.path, paths, note, selectable))
    return rows


def parse_selection(text: str, rows: list[Row]) -> tuple[set[int] | None, str | None]:
    """Parse ``1,3-5`` / ``all`` / ``none`` (1-based row numbers). Returns ``(indexes, None)``
    or ``(None, error)``. Never guesses: anything unclear is an error."""
    answer = text.strip().lower()
    selectable = {i for i, r in enumerate(rows, 1) if r.selectable}
    if answer == "all":
        return selectable, None
    if answer == "none":
        return set(), None
    if not answer:
        return None, "enter row numbers, 'all' or 'none'"
    chosen: set[int] = set()
    for part in answer.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", part)
        if not m:
            return None, f"not a row number or range: {part!r}"
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if lo > hi:
            return None, f"empty range: {part!r}"
        if lo < 1 or hi > len(rows):
            return None, f"out of range: {part!r} (rows 1-{len(rows)})"
        chosen.update(range(lo, hi + 1))
    bad = sorted(chosen - selectable)
    if bad:
        return None, f"row(s) {', '.join(map(str, bad))} cannot be integrated"
    return chosen, None


def selected_paths(indexes: set[int], rows: list[Row]) -> set[str]:
    return {p for i in indexes for p in rows[i - 1].paths}


# ---------------------------------------------------------------------------
# dependency warning (best effort)
# ---------------------------------------------------------------------------

_JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
_JS_RESOLVE = ("", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".json",
               "/index.js", "/index.jsx", "/index.ts", "/index.tsx", "/index.mjs")
_JS_IMPORT = re.compile(
    r"""(?:\bimport\s*(?:[^'"`;]*?\bfrom\s*)?|\bexport\s+[^'"`;]*?\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)(['"])(?P<spec>[^'"\n]+)\1"""
)
_PHP_INCLUDE = re.compile(
    r"""\b(?:require|include)(?:_once)?\b\s*\(?\s*(?P<dir>(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*)?(['"])(?P<spec>[^'"\n]+)\2""",
    re.IGNORECASE,
)
_PHP_USE = re.compile(r"^\s*use\s+(?:function\s+|const\s+)?(?P<names>[A-Za-z0-9_\\,\s{}]+?)\s*;", re.MULTILINE)


def _norm(path: str) -> str | None:
    p = posixpath.normpath(path)
    if p.startswith("../") or p == ".." or p.startswith("/"):
        return None
    return p


def _js_refs(path: str, text: str, added: set[str]) -> set[str]:
    base = posixpath.dirname(path)
    out: set[str] = set()
    for m in _JS_IMPORT.finditer(text):
        spec = m.group("spec")
        if not spec.startswith("."):
            continue  # bare package specifier
        target = _norm(posixpath.join(base, spec))
        if target is None:
            continue
        for suffix in _JS_RESOLVE:
            if target + suffix in added:
                out.add(target + suffix)
                break
    return out


def _php_use_names(text: str) -> list[str]:
    names: list[str] = []
    for m in _PHP_USE.finditer(text):
        raw = m.group("names")
        if "{" in raw:  # use App\Models\{User, Post};
            prefix, _, inner = raw.partition("{")
            names += [prefix.strip() + n.strip() for n in inner.rstrip("}").split(",") if n.strip()]
        else:
            names += [n.strip() for n in raw.split(",") if n.strip()]
    return [re.split(r"\s+as\s+", n, flags=re.IGNORECASE)[0].strip().strip("\\") for n in names]


def _php_refs(path: str, text: str, added: set[str]) -> set[str]:
    base = posixpath.dirname(path)
    out: set[str] = set()
    for m in _PHP_INCLUDE.finditer(text):
        spec = m.group("spec")
        cands = [posixpath.join(base, spec.lstrip("/"))] if m.group("dir") else [posixpath.join(base, spec), spec]
        for c in cands:
            t = _norm(c)
            if t and t in added:
                out.add(t)
    lower = {a.lower(): a for a in added if is_php(a)}
    for name in _php_use_names(text):
        parts = [p for p in name.split("\\") if p]
        if not parts:
            continue
        # PSR-4 style: App\Libraries\RateLimiter -> .../Libraries/RateLimiter.php
        for k in range(len(parts), min(2, len(parts)) - 1, -1):
            suffix = ("/".join(parts[-k:]) + ".php").lower()
            hits = [orig for low, orig in lower.items() if low == suffix or low.endswith("/" + suffix)]
            if hits:
                out.update(hits)
                break
    return out


def dependency_warnings(report: ReviewReport) -> list[Issue]:
    """WARNING when a selected file references a file that is *added* in the workspace
    but not selected (PHP require/include/use, JS/TS import/require). Best effort:
    ai-safe never selects anything automatically."""
    if report.selected is None:
        return []
    added = {c.path for c in report.changes if c.kind == "added"} - report.selected
    if not added:
        return []
    issues: list[Issue] = []
    for p in report.plan:
        if p.kind != "write" or p.source is None:
            continue
        try:
            text = p.source.decode("utf-8")
        except UnicodeDecodeError:
            continue
        suffix = PurePosixPath(p.path).suffix.lower()
        refs: set[str] = set()
        if is_php(p.path):
            refs = _php_refs(p.path, text, added)
        elif suffix in _JS_SUFFIXES:
            refs = _js_refs(p.path, text, added)
        for dep in sorted(refs):
            issues.append(Issue(Severity.WARNING, "unselected-dependency", p.path,
                                f"references {dep}, which the AI added but is not selected - it stays in the workspace"))
    return issues
