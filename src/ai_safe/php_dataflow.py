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
from ai_safe.classifier import is_sensitive_key, key_words
from ai_safe.php_calls import Arg, Sink, SinkSlot, classify_expression, fold_literal, is_php, iter_sink_slots, usable, user_ok

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
    reason: str  # "expression", "unresolved", "unresolved-include", "depth-limit", "unresolved-dynamic-call"

    def __str__(self) -> str:
        return f"php-dataflow: {self.reason} at {self.file}:{self.line}"


@dataclass(frozen=True)
class _Lit:
    file: str
    start: int
    end: int
    value: str


_ASSIGN_ANY = re.compile(r"(?<![\w$>:])\$(?P<name>[A-Za-z_]\w*)\s*=(?![=>])\s*(?P<rhs>[^;]{1,500});")
_GLOBALS_ASSIGN = re.compile(
    r"\$GLOBALS\s*\[\s*(?P<nq>['\"])(?P<name>[A-Za-z_]\w*)(?P=nq)\s*\]\s*=(?![=>])\s*" + _LIT + r"\s*;")
_THIS_ASSIGN = re.compile(r"\$this\s*->\s*(?P<name>[A-Za-z_]\w*)\s*=(?![=>])\s*" + _LIT + r"\s*;")
_CONST_STMT = re.compile(r"\bconst\s+(?P<body>[^;]{1,2000});")
_CONST_ITEM = re.compile(r"(?:^|,)\s*(?:[\w\\?]+\s+)?(?P<name>[A-Za-z_]\w*)\s*=\s*" + _LIT + r"\s*(?=,|$)")


class _Index:
    """Assignments, constants and properties of a set of PHP files."""

    def __init__(self, texts: dict[str, str]) -> None:
        self.texts = texts
        self.assigns: dict[str, dict[str, list[_Lit]]] = defaultdict(lambda: defaultdict(list))
        self.others: dict[str, dict[str, list[Arg]]] = defaultdict(lambda: defaultdict(list))
        self.props: dict[str, dict[str, list[_Lit]]] = defaultdict(lambda: defaultdict(list))
        self.consts: dict[str, list[_Lit]] = defaultdict(list)
        self._lines: dict[str, list[int]] = {}
        for rel, text in texts.items():
            for rx in (_ASSIGN, _GLOBALS_ASSIGN):
                for m in rx.finditer(text):
                    if lit := _lit(rel, m):
                        self.assigns[rel][m.group("name")].append(lit)
            for m in _ASSIGN_ANY.finditer(text):
                rhs = m.group("rhs").strip()
                if _LONE_LIT.fullmatch(rhs) and not (rhs[0] == '"' and "$" in rhs):
                    continue  # a literal: indexed above with exact offsets
                if folded := fold_literal(text, *m.span("rhs")):
                    # fallback literal (``getenv('X') ?: 'v'``) or constant concatenation
                    self.assigns[rel][m.group("name")].append(_Lit(rel, folded[1], folded[2], folded[0]))
                    continue
                self.others[rel][m.group("name")].append(classify_expression(rhs))
            for rx in (_PROPERTY, _THIS_ASSIGN):
                for m in rx.finditer(text):
                    if lit := _lit(rel, m):
                        self.props[rel][m.group("name")].append(lit)
            for m in _DEFINE.finditer(text):
                if lit := _lit(rel, m):
                    self.consts[m.group("name")].append(lit)
            for stmt in _CONST_STMT.finditer(text):
                base = stmt.start("body")
                for m in _CONST_ITEM.finditer(stmt.group("body")):
                    if lit := _lit(rel, m):
                        self.consts[m.group("name")].append(_Lit(rel, base + lit.start, base + lit.end, lit.value))
        self.files = sorted(texts)

    def line(self, rel: str, offset: int) -> int:
        if rel not in self._lines:
            self._lines[rel] = [0] + [m.end() for m in re.finditer("\n", self.texts[rel])]
        return bisect.bisect_right(self._lines[rel], offset)


_LONE_LIT = re.compile(r"(['\"])(?:\\.|(?!\1)[^\\\n])*\1")


def _lit(rel: str, m: re.Match[str]) -> _Lit | None:
    value = m.group("val")
    if m.group("q") == '"' and "$" in value:
        return None  # interpolated
    s, e = m.span("val")
    return _Lit(rel, s, e, value)


MAX_TRACE_DEPTH = 8

# Names a generic ``*connect`` wrapper argument must have to be traced: the
# wrapper's positions are a guess, so host/db/port variables must not become
# "credentials" (they would be replaced in every file).
_PW_SHORT_NAMES = {"p", "pw", "pwd", "pass", "pp", "pword", "passwd"}
_NOT_USER_WORDS = {"host", "hostname", "server", "db", "dbname", "database", "port", "timeout", "name",
                   "charset", "socket", "driver", "dsn", "path", "file", "dir", "url", "uri"}


def _generic_name_ok(slot: SinkSlot) -> bool:
    name = slot.arg.value
    if slot.role == "password":
        return is_sensitive_key(name) or name.lower() in _PW_SHORT_NAMES
    return not set(key_words(name)) & _NOT_USER_WORDS


@dataclass
class _Group:
    """User/password literals that reach one credential call."""

    sink: Sink
    generic: bool
    lits: dict[str, list[_Lit]] = field(default_factory=lambda: {"password": [], "user": []})


class _Ast:
    """tree-sitter index with the lookups the parameter worklist needs."""

    def __init__(self, texts: dict[str, str]) -> None:
        from ai_safe import php_ast

        funcs, self.calls = php_ast.index_php(texts)
        self.defs = {d.uid: d for ds in funcs.values() for d in ds}
        self.by_file: dict[str, list] = defaultdict(list)
        for d in self.defs.values():
            self.by_file[d.file].append(d)
        self.by_key: dict[str, list] = defaultdict(list)
        self.by_method: dict[str, list] = defaultdict(list)
        for cs in self.calls:
            for k in cs.callee_keys:
                self.by_key[k].append(cs)
            for m in cs.methods:
                self.by_method[m].append(cs)

    def enclosing(self, rel: str, offset: int):
        best = None
        for d in self.by_file.get(rel, ()):
            if d.body_span[0] <= offset < d.body_span[1]:
                if best is None or d.body_span[1] - d.body_span[0] < best.body_span[1] - best.body_span[0]:
                    best = d
        return best

    def callers(self, d) -> list:
        out = list(self.by_key.get(d.key, ()))
        if "::" in d.key:
            out += self.by_method.get(d.key.split("::", 1)[1], ())
        return out


def trace_php(texts: dict[str, str], *, ast: bool = False) -> tuple[list[FlowFinding], list[FlowWarning]]:
    """Trace every non-literal user/password argument of every credential
    call in ``texts`` (rel path -> text; non-PHP files are ignored). With
    ``ast=True`` (tree-sitter installed), parameters are also traced to the
    arguments of every call site of their function."""
    texts = {rel: t for rel, t in texts.items() if is_php(rel)}
    index = _Index(texts)
    scopes = _Scopes(texts)
    tree = _Ast(texts) if ast else None
    groups: dict[tuple, _Group] = {}
    warnings: list[FlowWarning] = []
    seen_warnings: set[FlowWarning] = set()

    def warn(rel: str, line: int, reason: str) -> None:
        w = FlowWarning(rel, line, reason)
        if w not in seen_warnings:
            seen_warnings.add(w)
            warnings.append(w)

    def resolve_in(rel: str, arg: Arg, line: int, role: str, *, is_param: bool = False) -> list[_Lit]:
        scope, truncated = scopes.of(rel)
        lits, reason = _resolve(arg, index, scope)
        if reason == "unresolved" and arg.kind in ("var", "prop") and scopes.has_unresolved(scope):
            lits, reason = _resolve(arg, index, index.files)[0], "unresolved-include"
        elif reason == "unresolved" and truncated:
            reason = "depth-limit"
        if reason == "unresolved" and is_param:
            reason = None  # a parameter: traced through its call sites instead
        if reason and role == "password":
            warn(rel, line, reason)
        return lits

    work: list[tuple[tuple[str, int], int, str, tuple, int]] = []
    for rel, text in sorted(texts.items()):
        for slot in iter_sink_slots(text, rel):
            gid = (rel, slot.call)
            group = groups.setdefault(gid, _Group(slot.sink, slot.generic))
            if slot.generic and slot.arg.kind in ("var", "const", "prop") and not _generic_name_ok(slot):
                continue
            is_param = False
            if tree is not None and slot.arg.kind == "var":
                d = tree.enclosing(rel, slot.call)
                if d is not None and slot.arg.value in d.params:
                    is_param = True
                    work.append((d.uid, d.params.index(slot.arg.value), slot.role, gid, 1))
            group.lits[slot.role].extend(resolve_in(rel, slot.arg, slot.line, slot.role, is_param=is_param))

    if tree is not None:
        _trace_parameters(tree, work, groups, resolve_in, warn)

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


def _trace_parameters(tree: _Ast, work: list, groups: dict, resolve_in, warn) -> None:
    """Worklist over (definition, parameter index, role, group): a parameter
    that reaches a credential call is traced to the matching argument of
    every call site of its function whose argument count fits the
    definition, recursively (depth-limited)."""
    seen: set[tuple] = set()
    while work:
        uid, idx, role, gid, depth = work.pop()
        if (uid, idx, role, gid) in seen:
            continue
        seen.add((uid, idx, role, gid))
        d = tree.defs[uid]
        group = groups[gid]
        if idx in d.defaults:
            s, e, value = d.defaults[idx]
            group.lits[role].append(_Lit(d.file, s, e, value))
        for cs in tree.callers(d):
            if idx >= len(cs.args) or not d.accepts(len(cs.args)):
                continue
            arg = cs.args[idx]
            if arg.kind == "str":
                group.lits[role].append(_Lit(cs.file, arg.start, arg.end, arg.value))
                continue
            caller = tree.defs.get(cs.enclosing) if cs.enclosing else None
            is_param = arg.kind == "var" and caller is not None and arg.value in caller.params
            group.lits[role].extend(resolve_in(cs.file, arg, cs.line, role, is_param=is_param))
            if is_param:
                if depth >= MAX_TRACE_DEPTH:
                    if role == "password":
                        warn(cs.file, cs.line, "depth-limit")
                    continue
                work.append((caller.uid, caller.params.index(arg.value), role, gid, depth + 1))

    # Dynamic calls whose target cannot be resolved: report their literals
    # at the positions of every credential-reaching parameter whose function
    # accepts that many arguments (decision 7a).
    reaching = sorted(seen)
    if not reaching:
        return
    for cs in tree.calls:
        if not cs.dynamic:
            continue
        hit = False
        for uid, idx, role, gid in reaching:
            if not tree.defs[uid].accepts(len(cs.args)):
                continue
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


def _resolve(arg: Arg, index: _Index, scope: list[str], depth: int = 0,
             seen: set | None = None) -> tuple[list[_Lit], str | None]:
    """Literals behind ``arg`` and, when there are none, why: "expression"
    (assigned something that cannot be followed), "unresolved" (never
    assigned in scope). Assignments from non-credential sources are silent.
    Variable copies (``$b = $a;``) are followed up to MAX_TRACE_DEPTH."""
    if arg.kind == "other":
        return [], "expression"
    if arg.kind not in ("var", "prop", "const"):
        return [], None  # str (Stage 1), num, array, source, empty
    seen = set() if seen is None else seen
    if (arg.kind, arg.value) in seen or depth > MAX_TRACE_DEPTH:
        return [], None
    seen.add((arg.kind, arg.value))
    if arg.kind == "var":
        lits = [lit for f in scope for lit in index.assigns[f].get(arg.value, [])]
        others = [o for f in scope for o in index.others[f].get(arg.value, [])]
    elif arg.kind == "prop":
        lits = [lit for f in scope for lit in index.props[f].get(arg.value, [])]
        others = []
    else:
        lits, others = list(index.consts.get(arg.value, [])), []
    reason = None
    for o in others:
        sub, r = _resolve(o, index, scope, depth + 1, seen)
        lits += sub
        reason = reason or (r if r != "unresolved" else None)
    if lits:
        return lits, None
    if reason:
        return [], reason
    return [], None if others else "unresolved"
