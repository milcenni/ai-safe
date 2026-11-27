"""PHP function and call-site index built with tree-sitter (optional extra).

Install with ``ai-safe[php]`` (``./install.sh --php``). Without it,
:func:`available` is False and :mod:`ai_safe.php_dataflow` traces variables,
includes and constants only.

Function keys are lowercased (PHP function and method names are
case-insensitive): ``name`` for functions, ``class::method`` for methods,
``closure@<file>:<offset>`` for closures and arrow functions. Call sites
resolve their callee to a *set* of keys: a method call on an object of
unknown class matches every method with that name (over-approximation).
Arguments are classified with :func:`ai_safe.php_calls.parse_args`, so the
resolver is shared with the regex-based passes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ai_safe.php_calls import Arg, parse_args
from ai_safe.security import SecurityError

try:  # optional dependency
    import tree_sitter
    import tree_sitter_php

    _LANGUAGE = tree_sitter.Language(tree_sitter_php.language_php())
except Exception:  # noqa: BLE001 - any import/ABI failure means "not available"
    _LANGUAGE = None


def available() -> bool:
    return _LANGUAGE is not None


def require() -> None:
    if not available():
        raise SecurityError(
            "scanner.php_dataflow=on requires the optional 'php' extra (tree-sitter); "
            "install ai-safe[php] or set scanner.php_dataflow: auto"
        )


@dataclass
class FunctionDef:
    key: str
    file: str
    params: list[str]  # names without "$"
    defaults: dict[int, tuple[int, int, str]]  # param index -> literal default (char span, value)
    body_span: tuple[int, int]  # char offsets


@dataclass
class CallSite:
    callee_keys: set[str]
    file: str
    args: list[Arg]
    enclosing: str | None  # key of the innermost enclosing FunctionDef
    dynamic: bool
    line: int = 0
    start: int = 0
    shift: int = field(default=0, repr=False)


_FUNC_NODES = {"function_definition", "method_declaration", "anonymous_function", "arrow_function"}
_CALL_NODES = {"function_call_expression", "member_call_expression", "nullsafe_member_call_expression",
               "scoped_call_expression", "object_creation_expression"}
_LIT_ASSIGN = r"\${name}\s*=\s*(?:(?P<q>['\"])(?P<val>[A-Za-z_\\][\w\\:]*)(?P=q)|(?P<fcc>[A-Za-z_\\][\w\\:]*)\s*\(\s*\.\.\.\s*\))\s*;"


class _Offsets:
    """tree-sitter reports byte offsets; Python strings use characters."""

    def __init__(self, text: str) -> None:
        self.ascii = text.isascii()
        if not self.ascii:
            self.table: list[int] = []
            for i, ch in enumerate(text):
                self.table.extend([i] * len(ch.encode("utf-8")))
            self.table.append(len(text))

    def __call__(self, b: int) -> int:
        return b if self.ascii else self.table[b]


def index_php(texts: dict[str, str]) -> tuple[dict[str, FunctionDef], list[CallSite]]:
    require()
    parser = tree_sitter.Parser(_LANGUAGE)
    funcs: dict[str, FunctionDef] = {}
    calls: list[CallSite] = []
    for rel, text in sorted(texts.items()):
        tree = parser.parse(text.encode("utf-8"))
        _Walker(rel, text, _Offsets(text), funcs, calls).walk(tree.root_node)
    return funcs, calls


class _Walker:
    def __init__(self, rel: str, text: str, off: _Offsets, funcs: dict[str, FunctionDef], calls: list[CallSite]) -> None:
        self.rel, self.text, self.off, self.funcs, self.calls = rel, text, off, funcs, calls
        self.classes: list[str] = []
        self.enclosing: list[str] = []

    def _t(self, node) -> str:
        return self.text[self.off(node.start_byte):self.off(node.end_byte)]

    def walk(self, node) -> None:
        pushed_class = pushed_func = False
        if node.type in ("class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"):
            name = node.child_by_field_name("name")
            self.classes.append(self._t(name).lower() if name else "?")
            pushed_class = True
        elif node.type in _FUNC_NODES:
            self.enclosing.append(self._function(node))
            pushed_func = True
        elif node.type in _CALL_NODES:
            self._call(node)
        for child in node.children:
            self.walk(child)
        if pushed_class:
            self.classes.pop()
        if pushed_func:
            self.enclosing.pop()

    def _function(self, node) -> str:
        name = node.child_by_field_name("name")
        if node.type == "method_declaration":
            key = f"{self.classes[-1] if self.classes else '?'}::{self._t(name).lower()}"
        elif node.type == "function_definition":
            key = self._t(name).lower().lstrip("\\")
        else:
            key = f"closure@{self.rel}:{self.off(node.start_byte)}"
        params, defaults = [], {}
        plist = node.child_by_field_name("parameters")
        for p in (plist.named_children if plist else []):
            if p.type not in ("simple_parameter", "property_promotion_parameter", "variadic_parameter"):
                continue
            var = p.child_by_field_name("name")
            params.append(self._t(var).lstrip("$") if var else "")
            default = p.child_by_field_name("default_value")
            if default is not None and default.type in ("string", "encapsed_string"):
                s, e = self.off(default.start_byte) + 1, self.off(default.end_byte) - 1
                value = self.text[s:e]
                if not (default.type == "encapsed_string" and "$" in value):
                    defaults[len(params) - 1] = (s, e, value)
        body = node.child_by_field_name("body")
        span = (self.off(body.start_byte), self.off(body.end_byte)) if body else (0, 0)
        self.funcs.setdefault(key, FunctionDef(key, self.rel, params, defaults, span))
        return key

    def _call(self, node) -> None:
        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            args_node = next((c for c in node.children if c.type == "arguments"), None)
        if args_node is None:
            return
        args = parse_args(self.text, self.off(args_node.start_byte))
        if args is None:
            return
        res = self._callee(node, args)
        if res is None:
            return  # call_user_func() without arguments
        keys, new_args, dynamic = res
        if new_args is not None:
            args = new_args
        start = self.off(node.start_byte)
        self.calls.append(CallSite(set(keys), self.rel, args, self.enclosing[-1] if self.enclosing else None,
                                   dynamic, node.start_point[0] + 1, start))

    def _callee(self, node, args: list[Arg]):
        t = node.type
        if t == "object_creation_expression":
            cls = next((c for c in node.named_children if c.type in ("name", "qualified_name")), None)
            if cls is None:
                return set(), None, True
            return {f"{self._t(cls).split(chr(92))[-1].lower()}::__construct"}, None, False
        if t in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
            name = node.child_by_field_name("name")
            if name is None or name.type != "name":
                return set(), None, True  # $obj->$method()
            return {_Method(self._t(name).lower())}, None, False
        fn = node.child_by_field_name("function")
        if fn is None:
            return set(), None, True
        if fn.type in ("name", "qualified_name"):
            fname = self._t(fn).split("\\")[-1].lower()
            if fname in ("call_user_func", "call_user_func_array"):
                return self._call_user_func(fname, args)
            return {fname}, None, False
        if fn.type == "variable_name":
            target = self._local_callable(self._t(fn).lstrip("$"), self.off(node.start_byte))
            return ({target}, None, False) if target else (set(), None, True)
        return set(), None, True

    def _call_user_func(self, fname: str, args: list[Arg]):
        if not args:
            return None
        first = args[0]
        if fname == "call_user_func":
            rest = args[1:]
        else:
            rest = parse_args(self.text, args[1].start) if len(args) > 1 and args[1].kind == "array" else None
            if rest is None:
                return set(), None, True
        target = None
        if first.kind == "str":
            target = _callable_key(first.value)
        elif first.kind == "array":
            items = parse_args(self.text, first.start) or []
            if len(items) == 2 and items[1].kind == "str":
                target = _Method(items[1].value.lower())
        elif first.kind == "var":
            target = self._local_callable(first.value, first.start)
        if target is None:
            return set(), rest, True
        return {target}, rest, False

    def _local_callable(self, var: str, before: int):
        """``$f = 'name';`` or ``$f = name(...);`` earlier in the same text."""
        rx = re.compile(_LIT_ASSIGN.replace("{name}", re.escape(var)))
        target = None
        for m in rx.finditer(self.text, 0, before):
            target = _callable_key(m.group("val") or m.group("fcc"))
        return target


class _Method(str):
    """A method name whose class is unknown: matches every ``*::name``."""


def _callable_key(name: str):
    name = name.lstrip("\\")
    if "::" in name:
        return _Method(name.split("::", 1)[1].lower())
    return name.split("\\")[-1].lower()


def resolve_keys(keys: set[str], funcs: dict[str, FunctionDef]) -> set[str]:
    """Expand ``_Method`` names to every ``class::name`` function key."""
    out: set[str] = set()
    for k in keys:
        if isinstance(k, _Method):
            out.update(f for f in funcs if f.endswith("::" + k))
        else:
            out.add(k)
    return out
