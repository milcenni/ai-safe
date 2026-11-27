"""Repo-level tracing of PHP credential-call arguments back to literals.

Stage 1 (:mod:`ai_safe.php_calls`) finds literals passed directly to a
credential call. This pass follows the other user/password arguments:

* ``$var`` to every ``$var = '<literal>';`` in scope (all of them: over-
  approximate, a reassigned variable reports every literal);
* constants (``define('X', '<lit>')``, ``const X = '<lit>'``, class
  constants) to their literal anywhere in the repository;
* properties (``$this->x``, ``self::$x``) to ``var/public/private/... $x =
  '<lit>'`` declarations in scope.

Non-credential sources (superglobals, ``getenv``, ``env``, ``config``) are
neither reported nor warned about. Any other expression produces a
:class:`FlowWarning` with file and line only, never a value. Usernames are
reported only when the same call's password resolved to a literal.
"""

from __future__ import annotations

import bisect
import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass

from ai_safe.models import Category
from ai_safe.php_calls import SinkSlot, is_php, iter_sink_slots, usable, user_ok

_LIT = r"(?P<q>['\"])(?P<val>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)"
_ASSIGN = re.compile(r"(?<![\w$>:])\$(?P<name>[A-Za-z_]\w*)\s*=(?![=>])\s*" + _LIT + r"\s*;")
_DEFINE = re.compile(r"(?i)\bdefine\s*\(\s*(?P<nq>['\"])\\?(?P<name>[A-Za-z_]\w*)(?P=nq)\s*,\s*" + _LIT + r"\s*[,)]")
_CONST = re.compile(r"\bconst\s+(?:[\w\\?]+\s+)?(?P<name>[A-Za-z_]\w*)\s*=\s*" + _LIT + r"\s*;")
_PROPERTY = re.compile(
    r"\b(?:var|public|protected|private|static|readonly)\s+(?:(?:static|readonly)\s+)*(?:\??[\w\\]+\s+)?"
    r"\$(?P<name>[A-Za-z_]\w*)\s*=\s*" + _LIT + r"\s*;"
)

_INCLUDE = re.compile(r"(?<![\w$>:])(?:include|require)(?:_once)?\b\s*(?P<expr>[^;]{1,300});")
_INC_LIT = r"(?P<q>['\"])(?P<path>[^'\"$\n]+)(?P=q)"
_INC_FORMS = (
    (re.compile(r"^\(?\s*" + _INC_LIT + r"\s*\)?$"), "plain"),
    (re.compile(r"^\(?\s*__DIR__\s*\.\s*" + _INC_LIT + r"\s*\)?$"), "dir"),
    (re.compile(r"^\(?\s*dirname\s*\(\s*__FILE__\s*\)\s*\.\s*" + _INC_LIT + r"\s*\)?$"), "dir"),
    (re.compile(r"^\(?\s*dirname\s*\(\s*__DIR__\s*\)\s*\.\s*" + _INC_LIT + r"\s*\)?$"), "parent"),
)
MAX_INCLUDE_DEPTH = 8


def include_graph(texts: dict[str, str]) -> tuple[dict[str, set[str]], set[str]]:
    """Edges file -> included files (static paths that exist in ``texts``),
    and the files that contain an include that could not be resolved."""
    edges: dict[str, set[str]] = defaultdict(set)
    unresolved: set[str] = set()
    for rel, text in texts.items():
        for m in _INCLUDE.finditer(text):
            target = _resolve_include(rel, m.group("expr").strip(), texts)
            if target is None:
                unresolved.add(rel)
            elif target != rel:
                edges[rel].add(target)
    return edges, unresolved


def _resolve_include(rel: str, expr: str, texts: dict[str, str]) -> str | None:
    for rx, form in _INC_FORMS:
        m = rx.match(expr)
        if not m:
            continue
        path = m.group("path")
        here = posixpath.dirname(rel)
        if form == "dir":
            bases = [here]
        elif form == "parent":
            bases = [posixpath.dirname(here)]
        else:  # include_path semantics: the including file's directory, then the root
            bases = [here, ""]
        for base in bases:
            cand = posixpath.normpath(posixpath.join(base, path.lstrip("/") if form != "plain" else path))
            if cand in texts:
                return cand
        return None
    return None


@dataclass(frozen=True)
class FlowFinding:
    file: str
    start: int
    end: int
    line: int
    secret: str
    role: str
    category: Category
    key: str
    rule_id: str = "php-dataflow"


@dataclass(frozen=True)
class FlowWarning:
    file: str
    line: int
    reason: str  # "expression", "unresolved-include", "depth-limit", "unresolved-dynamic-call"

    def __str__(self) -> str:
        return f"php-dataflow: {self.reason} at {self.file}:{self.line}"


@dataclass(frozen=True)
class _Lit:
    file: str
    start: int
    end: int
    value: str


class _Index:
    """Literal assignments, constants and properties of a set of PHP files."""

    def __init__(self, texts: dict[str, str]) -> None:
        self.texts = texts
        self.assigns: dict[str, dict[str, list[_Lit]]] = defaultdict(lambda: defaultdict(list))
        self.props: dict[str, dict[str, list[_Lit]]] = defaultdict(lambda: defaultdict(list))
        self.consts: dict[str, list[_Lit]] = defaultdict(list)
        self._lines: dict[str, list[int]] = {}
        for rel, text in texts.items():
            for m in _ASSIGN.finditer(text):
                if lit := _lit(rel, m):
                    self.assigns[rel][m.group("name")].append(lit)
            for m in _PROPERTY.finditer(text):
                if lit := _lit(rel, m):
                    self.props[rel][m.group("name")].append(lit)
            for rx in (_DEFINE, _CONST):
                for m in rx.finditer(text):
                    if lit := _lit(rel, m):
                        self.consts[m.group("name")].append(lit)

    def line(self, rel: str, offset: int) -> int:
        if rel not in self._lines:
            self._lines[rel] = [0] + [m.end() for m in re.finditer("\n", self.texts[rel])]
        return bisect.bisect_right(self._lines[rel], offset)


def _lit(rel: str, m: re.Match[str]) -> _Lit | None:
    value = m.group("val")
    if m.group("q") == '"' and "$" in value:
        return None  # interpolated
    s, e = m.span("val")
    return _Lit(rel, s, e, value)


def trace_php(texts: dict[str, str]) -> tuple[list[FlowFinding], list[FlowWarning]]:
    """Trace every non-literal user/password argument of every credential
    call in ``texts`` (rel path -> text; non-PHP files are ignored)."""
    texts = {rel: t for rel, t in texts.items() if is_php(rel)}
    index = _Index(texts)
    scopes = _Scopes(texts)
    findings: dict[tuple[str, int, int], FlowFinding] = {}
    warnings: list[FlowWarning] = []
    for rel, text in sorted(texts.items()):
        calls: dict[int, list[SinkSlot]] = defaultdict(list)
        for slot in iter_sink_slots(text, rel):
            calls[slot.call].append(slot)
        for slots in calls.values():
            resolved: dict[str, list[_Lit]] = {}
            scope, truncated = scopes.of(rel)
            for slot in slots:
                lits, warn = _resolve(slot, index, scope)
                if not lits and not warn and slot.arg.kind in ("var", "prop") and scopes.has_unresolved(scope):
                    # A dynamic include may bring the value in: look it up
                    # repository-wide (over-approximate) and say so.
                    lits = _resolve(slot, index, sorted(texts))[0]
                    warn = "unresolved-include"
                if not lits and not warn and truncated and slot.arg.kind in ("var", "prop"):
                    warn = "depth-limit"
                resolved[slot.role] = lits
                if warn and slot.role == "password":
                    w = FlowWarning(rel, slot.line, warn)
                    if w not in warnings:
                        warnings.append(w)
            generic = slots[0].generic
            pw = [lit for lit in resolved.get("password", []) if usable(lit.value, generic)]
            if not pw:
                continue
            users = [lit for lit in resolved.get("user", []) if user_ok(lit.value, generic)]
            user_key, pw_key = slots[0].sink.keys
            for role, lits, key in (("password", pw, pw_key), ("user", users, user_key)):
                for lit in lits:
                    k = (lit.file, lit.start, lit.end)
                    if k not in findings:
                        findings[k] = FlowFinding(lit.file, lit.start, lit.end, index.line(lit.file, lit.start),
                                                  lit.value, role, slots[0].sink.category, key)
    return sorted(findings.values(), key=lambda f: (f.file, f.start)), warnings


class _Scopes:
    """Files whose variables and properties are visible in a file: its
    undirected include-graph component (covers files included by a common
    entry file), up to MAX_INCLUDE_DEPTH hops."""

    def __init__(self, texts: dict[str, str]) -> None:
        edges, self.unresolved = include_graph(texts)
        self.adj: dict[str, set[str]] = defaultdict(set)
        for a, targets in edges.items():
            for b in targets:
                self.adj[a].add(b)
                self.adj[b].add(a)
        self._cache: dict[str, tuple[list[str], bool]] = {}

    def of(self, rel: str) -> tuple[list[str], bool]:
        """(files in scope, depth limit hit)."""
        if rel not in self._cache:
            seen, frontier, truncated = {rel}, [rel], False
            for depth in range(MAX_INCLUDE_DEPTH + 1):
                nxt = []
                for f in frontier:
                    for g in self.adj.get(f, ()):
                        if g not in seen:
                            if depth == MAX_INCLUDE_DEPTH:
                                truncated = True
                                continue
                            seen.add(g)
                            nxt.append(g)
                frontier = nxt
                if not frontier:
                    break
            self._cache[rel] = (sorted(seen), truncated)
        return self._cache[rel]

    def has_unresolved(self, files: list[str]) -> bool:
        return any(f in self.unresolved for f in files)


def _resolve(slot: SinkSlot, index: _Index, scope: list[str]) -> tuple[list[_Lit], str | None]:
    arg = slot.arg
    if arg.kind == "var":
        return [lit for f in scope for lit in index.assigns[f].get(arg.value, [])], None
    if arg.kind == "prop":
        return [lit for f in scope for lit in index.props[f].get(arg.value, [])], None
    if arg.kind == "const":
        return list(index.consts.get(arg.value, [])), None
    if arg.kind == "other":
        return [], "expression"
    return [], None  # str (Stage 1), num, array, source, empty
