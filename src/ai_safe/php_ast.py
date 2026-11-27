"""PHP function and call-site index built with tree-sitter (optional extra).

Install with ``ai-safe[php]`` (``./install.sh --php``). Without it,
:func:`available` is False and :mod:`ai_safe.php_dataflow` traces variables,
includes and constants only.

Function keys are lowercased (PHP function and method names are
case-insensitive): ``name`` for functions, ``class::method`` for methods,
``closure@<file>:<offset>`` for closures and arrow functions. Several
definitions may share a key (two copies of ``class Db`` in ``admin/`` and
``public/``); all are kept. Call sites name their callee exactly where the
code does (``foo()``, ``new Db()``, ``Db::open()``, ``self::open()``,
``parent::__construct()``, ``call_user_func('foo')``); only a method call on
an object of unknown class (``$o->m()``, ``[$o, 'm']``) matches every method
called ``m`` (over-approximation). Arguments are classified with
:func:`ai_safe.php_calls.parse_args`, so the resolver is shared with the
regex-based passes. The tree walk is iterative: nesting depth cannot exhaust
the Python stack.
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
    start: int = 0  # char offset of the definition: (file, start) identifies it
    required: int = 0  # parameters without a default
    variadic: bool = False

    @property
    def uid(self) -> tuple[str, int]:
        return (self.file, self.start)

    def accepts(self, n_args: int) -> bool:
        return n_args >= self.required and (self.variadic or n_args <= len(self.params))


@dataclass
class CallSite:
    callee_keys: set[str]  # exact function keys
    file: str
    args: list[Arg]
    enclosing: tuple[str, int] | None  # uid of the innermost enclosing FunctionDef
    dynamic: bool  # target cannot be resolved at all
    line: int = 0
    start: int = 0
    methods: set[str] = field(default_factory=set)  # method names on an object of unknown class


_FUNC_NODES = {"function_definition", "method_declaration", "anonymous_function", "arrow_function"}
_CLASS_NODES = {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}
_CALL_NODES = {"function_call_expression", "member_call_expression", "nullsafe_member_call_expression",
               "scoped_call_expression", "object_creation_expression"}
_LIT_ASSIGN = r"\${name}\s*=\s*(?:(?P<q>['\"])(?P<val>[A-Za-z_\\][\w\\:]*)(?P=q)|(?P<fcc>[A-Za-z_\\][\w\\:]*)\s*\(\s*\.\.\.\s*\))\s*;"
_EXIT = object()


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


def index_php(texts: dict[str, str]) -> tuple[dict[str, list[FunctionDef]], list[CallSite]]:
    """Function definitions by key (several per key are possible) and every
    call site of ``texts``."""
    require()
    parser = tree_sitter.Parser(_LANGUAGE)
    funcs: dict[str, list[FunctionDef]] = {}
    calls: list[CallSite] = []
    for rel, text in sorted(texts.items()):
        tree = parser.parse(text.encode("utf-8"))
        _Walker(rel, text, _Offsets(text), funcs, calls).walk(tree.root_node)
    return funcs, calls


class _Walker:
    def __init__(self, rel: str, text: str, off: _Offsets, funcs: dict[str, list[FunctionDef]],
                 calls: list[CallSite]) -> None:
        self.rel, self.text, self.off, self.funcs, self.calls = rel, text, off, funcs, calls
        self.classes: list[tuple[str, str | None]] = []  # (class, parent class)
        self.enclosing: list[tuple[str, int]] = []
        self._assign_cache: dict[str, list[tuple[int, object]]] = {}

    def _t(self, node) -> str:
        return self.text[self.off(node.start_byte):self.off(node.end_byte)]

    def walk(self, root) -> None:
        stack: list = [root]
        while stack:
            item = stack.pop()
            if isinstance(item, tuple) and item[0] is _EXIT:
                getattr(self, item[1]).pop()
                continue
            node = item
            if node.type in _CLASS_NODES:
                self.classes.append(self._class(node))
                stack.append((_EXIT, "classes"))
            elif node.type in _FUNC_NODES:
                self.enclosing.append(self._function(node))
                stack.append((_EXIT, "enclosing"))
            elif node.type in _CALL_NODES:
                self._call(node)
            stack.extend(reversed(node.children))

    def _class(self, node) -> tuple[str, str | None]:
        name = node.child_by_field_name("name")
        parent = None
        base = next((c for c in node.children if c.type == "base_clause"), None)
        if base is not None:
            pname = next((c for c in base.named_children if c.type in ("name", "qualified_name")), None)
            if pname is not None:
                parent = _short(self._t(pname))
        return (_short(self._t(name)) if name else "?", parent)

    def _function(self, node) -> tuple[str, int]:
        name = node.child_by_field_name("name")
        start = self.off(node.start_byte)
        if node.type == "method_declaration":
            key = f"{self.classes[-1][0] if self.classes else '?'}::{self._t(name).lower()}"
        elif node.type == "function_definition":
            key = _short(self._t(name))
        else:
            key = f"closure@{self.rel}:{start}"
        params, defaults, required, variadic = [], {}, 0, False
        plist = node.child_by_field_name("parameters")
        for p in (plist.named_children if plist else []):
            if p.type not in ("simple_parameter", "property_promotion_parameter", "variadic_parameter"):
                continue
            var = p.child_by_field_name("name")
            params.append(self._t(var).lstrip("$") if var else "")
            default = p.child_by_field_name("default_value")
            if p.type == "variadic_parameter":
                variadic = True
            elif default is None:
                required = len(params)
            if default is not None and default.type in ("string", "encapsed_string"):
                s, e = self.off(default.start_byte) + 1, self.off(default.end_byte) - 1
                value = self.text[s:e]
                if not (default.type == "encapsed_string" and "$" in value):
                    defaults[len(params) - 1] = (s, e, value)
        body = node.child_by_field_name("body")
        span = (self.off(body.start_byte), self.off(body.end_byte)) if body else (0, 0)
        self.funcs.setdefault(key, []).append(
            FunctionDef(key, self.rel, params, defaults, span, start, required, variadic))
        return (self.rel, start)

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
            return
        keys, methods, new_args, dynamic = res
        if new_args is not None:
            args = new_args
        if not keys and not methods and not dynamic:
            return
        self.calls.append(CallSite(keys, self.rel, args, self.enclosing[-1] if self.enclosing else None,
                                   dynamic, node.start_point[0] + 1, self.off(node.start_byte), methods))

    def _scoped_class(self, scope_text: str) -> str | None:
        s = scope_text.strip().lower()
        if s in ("self", "static"):
            return self.classes[-1][0] if self.classes else None
        if s == "parent":
            return self.classes[-1][1] if self.classes else None
        if s.startswith("$"):
            return None
        return _short(scope_text)

    def _callee(self, node, args: list[Arg]):
        """(exact keys, unknown-class method names, replacement args, dynamic)."""
        t = node.type
        if t == "object_creation_expression":
            cls = next((c for c in node.named_children if c.type in ("name", "qualified_name")), None)
            if cls is None:
                return None  # new $cls(...) / anonymous class: not a credential call
            return {f"{_short(self._t(cls))}::__construct"}, set(), None, False
        if t in ("member_call_expression", "nullsafe_member_call_expression"):
            name = node.child_by_field_name("name")
            if name is None or name.type != "name":
                return set(), set(), None, True  # $obj->$method()
            return set(), {self._t(name).lower()}, None, False
        if t == "scoped_call_expression":
            name = node.child_by_field_name("name")
            scope = node.child_by_field_name("scope")
            if name is None or name.type != "name":
                return set(), set(), None, True
            m = self._t(name).lower()
            cls = self._scoped_class(self._t(scope)) if scope is not None else None
            if cls is None:
                if scope is not None and self._t(scope).strip().startswith("$"):
                    return set(), {m}, None, False  # $cls::m(): class unknown
                return None  # parent:: without a known parent
            return {f"{cls}::{m}"}, set(), None, False
        fn = node.child_by_field_name("function")
        if fn is None:
            return set(), set(), None, True
        if fn.type in ("name", "qualified_name"):
            fname = _short(self._t(fn))
            if fname in ("call_user_func", "call_user_func_array"):
                return self._call_user_func(fname, args)
            return {fname}, set(), None, False
        if fn.type == "variable_name":
            target = self._local_callable(self._t(fn).lstrip("$"), self.off(node.start_byte))
            return _target(target) + (None, target is None)
        return set(), set(), None, True

    def _call_user_func(self, fname: str, args: list[Arg]):
        if not args:
            return None
        first = args[0]
        if fname == "call_user_func":
            rest = args[1:]
        else:
            rest = parse_args(self.text, args[1].start) if len(args) > 1 and args[1].kind == "array" else None
            if rest is None:
                return set(), set(), None, True
        target = None
        if first.kind == "str":
            target = _callable_key(first.value)
        elif first.kind == "array":
            items = parse_args(self.text, first.start) or []
            if len(items) == 2 and items[1].kind == "str":
                if items[0].kind == "str":
                    target = f"{_short(items[0].value)}::{items[1].value.lower()}"
                elif items[0].kind == "const" and items[0].value.lower() == "class":
                    cls = self.text[items[0].start:items[0].end].rsplit("::", 1)[0]
                    target = f"{_short(cls)}::{items[1].value.lower()}"
                else:
                    target = _Method(items[1].value.lower())
        elif first.kind == "var":
            target = self._local_callable(first.value, first.start)
        return _target(target) + (rest, target is None)

    def _local_callable(self, var: str, before: int):
        """``$f = 'name';`` or ``$f = name(...);`` earlier in the same text."""
        if var not in self._assign_cache:
            rx = re.compile(_LIT_ASSIGN.replace("{name}", re.escape(var)))
            self._assign_cache[var] = [(m.start(), _callable_key(m.group("val") or m.group("fcc")))
                                       for m in rx.finditer(self.text)]
        target = None
        for pos, key in self._assign_cache[var]:
            if pos >= before:
                break
            target = key
        return target


class _Method(str):
    """A method name whose class is unknown: matches every ``*::name``."""


def _short(name: str) -> str:
    return name.strip().lstrip("\\").split("\\")[-1].lower()


def _callable_key(name: str):
    name = name.lstrip("\\")
    if "::" in name:
        cls, m = name.split("::", 1)
        return f"{_short(cls)}::{m.lower()}"
    return _short(name)


def _target(target) -> tuple[set[str], set[str]]:
    if target is None:
        return set(), set()
    if isinstance(target, _Method):
        return set(), {str(target)}
    return {target}, set()
