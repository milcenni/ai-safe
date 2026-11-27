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
from dataclasses import dataclass, field

from ai_safe.models import Category
from ai_safe.php_calls import Arg, Sink, SinkSlot, is_php, iter_sink_slots, usable, user_ok

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


MAX_TRACE_DEPTH = 8


@dataclass
class _Group:
    """User/password literals that reach one credential call."""

    sink: Sink
    generic: bool
    lits: dict[str, list[_Lit]] = field(default_factory=lambda: {"password": [], "user": []})


def trace_php(texts: dict[str, str], *, ast: bool = False) -> tuple[list[FlowFinding], list[FlowWarning]]:
    """Trace every non-literal user/password argument of every credential
    call in ``texts`` (rel path -> text; non-PHP files are ignored). With
    ``ast=True`` (tree-sitter installed), parameters are also traced to the
    arguments of every call site of their function."""
    texts = {rel: t for rel, t in texts.items() if is_php(rel)}
    index = _Index(texts)
    scopes = _Scopes(texts)
    groups: dict[tuple, _Group] = {}
    warnings: list[FlowWarning] = []

    def warn(rel: str, line: int, reason: str) -> None:
        w = FlowWarning(rel, line, reason)
        if w not in warnings:
            warnings.append(w)

    def resolve_in(rel: str, arg, line: int, role: str) -> list[_Lit]:
        scope, truncated = scopes.of(rel)
        lits, reason = _resolve(arg, index, scope)
        if not lits and not reason and arg.kind in ("var", "prop") and scopes.has_unresolved(scope):
            lits, reason = _resolve(arg, index, sorted(texts))[0], "unresolved-include"
        if not lits and not reason and truncated and arg.kind in ("var", "prop"):
            reason = "depth-limit"
        if reason and role == "password":
            warn(rel, line, reason)
        return lits

    slots_by_group: dict[tuple, list[SinkSlot]] = defaultdict(list)
    for rel, text in sorted(texts.items()):
        for slot in iter_sink_slots(text, rel):
            gid = (rel, slot.call)
            slots_by_group[gid].append(slot)
            group = groups.setdefault(gid, _Group(slot.sink, slot.generic))
            group.lits[slot.role].extend(resolve_in(rel, slot.arg, slot.line, slot.role))

    if ast:
        _trace_parameters(texts, groups, slots_by_group, resolve_in, warn)

    findings: dict[tuple[str, int, int], FlowFinding] = {}
    for group in groups.values():
        pw = [lit for lit in group.lits["password"] if usable(lit.value, group.generic)]
        if not pw:
            continue
        users = [lit for lit in group.lits["user"] if user_ok(lit.value, group.generic)]
        user_key, pw_key = group.sink.keys
        for role, lits, key in (("password", pw, pw_key), ("user", users, user_key)):
            for lit in lits:
                k = (lit.file, lit.start, lit.end)
                if k not in findings:
                    findings[k] = FlowFinding(lit.file, lit.start, lit.end, index.line(lit.file, lit.start),
                                              lit.value, role, group.sink.category, key)
    return sorted(findings.values(), key=lambda f: (f.file, f.start)), warnings


def _trace_parameters(texts, groups, slots_by_group, resolve_in, warn) -> None:
    """Worklist over (function, parameter index, role, group): a parameter
    that reaches a credential call is traced to the matching argument of
    every call site of its function, recursively (depth-limited)."""
    from ai_safe import php_ast

    funcs, calls = php_ast.index_php(texts)
    by_callee: dict[str, list] = defaultdict(list)
    for cs in calls:
        for key in php_ast.resolve_keys(cs.callee_keys, funcs):
            by_callee[key].append(cs)

    def enclosing(rel: str, offset: int):
        best = None
        for f in funcs.values():
            if f.file == rel and f.body_span[0] <= offset < f.body_span[1]:
                if best is None or f.body_span[1] - f.body_span[0] < best.body_span[1] - best.body_span[0]:
                    best = f
        return best

    work: list[tuple[str, int, str, tuple, int]] = []
    for gid, slots in slots_by_group.items():
        for slot in slots:
            if slot.arg.kind != "var":
                continue
            f = enclosing(slot.file, slot.call)
            if f is not None and slot.arg.value in f.params:
                work.append((f.key, f.params.index(slot.arg.value), slot.role, gid, 1))

    seen: set[tuple[str, int, str, tuple]] = set()
    while work:
        fkey, idx, role, gid, depth = work.pop()
        if (fkey, idx, role, gid) in seen:
            continue
        seen.add((fkey, idx, role, gid))
        fdef = funcs[fkey]
        group = groups[gid]
        if idx in fdef.defaults:
            s, e, value = fdef.defaults[idx]
            group.lits[role].append(_Lit(fdef.file, s, e, value))
        for cs in by_callee.get(fkey, ()):
            if idx >= len(cs.args):
                continue
            arg = cs.args[idx]
            if arg.kind == "str":
                group.lits[role].append(_Lit(cs.file, arg.start, arg.end, arg.value))
                continue
            group.lits[role].extend(resolve_in(cs.file, arg, cs.line, role))
            caller = funcs.get(cs.enclosing) if cs.enclosing else None
            if arg.kind == "var" and caller is not None and arg.value in caller.params:
                if depth >= MAX_TRACE_DEPTH:
                    if role == "password":
                        warn(cs.file, cs.line, "depth-limit")
                    continue
                work.append((caller.key, caller.params.index(arg.value), role, gid, depth + 1))

    # Dynamic calls whose target cannot be resolved: report their literals
    # at the positions of every credential-reaching parameter (decision 7a).
    reaching = sorted({(fkey, idx, role, gid) for fkey, idx, role, gid in seen})
    for cs in calls:
        if not cs.dynamic or not reaching:
            continue
        hit = False
        for fkey, idx, role, gid in reaching:
            if idx < len(cs.args) and cs.args[idx].kind == "str":
                dyn = ("dynamic", cs.file, cs.start, gid)
                group = groups.setdefault(dyn, _Group(groups[gid].sink, groups[gid].generic))
                arg = cs.args[idx]
                lit = _Lit(cs.file, arg.start, arg.end, arg.value)
                if lit not in group.lits[role]:
                    group.lits[role].append(lit)
                hit = hit or role == "password"
        if hit:
            warn(cs.file, cs.line, "unresolved-dynamic-call")


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


def _resolve(arg: Arg, index: _Index, scope: list[str]) -> tuple[list[_Lit], str | None]:
    if arg.kind == "var":
        return [lit for f in scope for lit in index.assigns[f].get(arg.value, [])], None
    if arg.kind == "prop":
        return [lit for f in scope for lit in index.props[f].get(arg.value, [])], None
    if arg.kind == "const":
        return list(index.consts.get(arg.value, [])), None
    if arg.kind == "other":
        return [], "expression"
    return [], None  # str (Stage 1), num, array, source, empty
