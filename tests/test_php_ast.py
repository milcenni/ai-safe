"""Phase C: credentials traced through PHP function and method parameters
(optional tree-sitter extra). Values are synthetic and generated at runtime."""

import random

import pytest

pytest.importorskip("tree_sitter_php")

from ai_safe.php_dataflow import trace_php  # noqa: E402
from conftest import short_word  # noqa: E402

_R = random.Random(5)


def up() -> tuple[str, str]:
    return short_word(_R, 7), short_word(_R, 5) + "4"


def secrets(texts: dict[str, str]) -> set[str]:
    return {f.secret for f in trace_php(texts, ast=True)[0]}


WRAPPER = "function open_db($u, $p) { return mysqli_connect('db', $u, $p); }\n"


def test_wrapper_function_same_file():
    u, p = up()
    assert secrets({"a.php": f"<?php\n{WRAPPER}open_db('{u}', '{p}');\n"}) == {u, p}


def test_wrapper_cross_file():
    u, p = up()
    texts = {"lib.php": f"<?php\n{WRAPPER}", "index.php": f"<?php\nrequire 'lib.php';\n$c = open_db('{u}', '{p}');\n"}
    assert secrets(texts) == {u, p}


def test_two_level_wrapper():
    u, p = up()
    text = ("<?php\nfunction custom_connectv2($u, $pp) { return new PDO('mysql:host=db', $u, $pp); }\n"
            "function custom_open($u, $p) { return custom_connectv2($u, $p); }\n"
            f"custom_open('{u}', '{p}');\n")
    assert secrets({"a.php": text}) == {u, p}


def test_call_user_func_literal_name():
    u, p = up()
    a = secrets({"a.php": f"<?php\n{WRAPPER}$c = call_user_func('open_db', '{u}', '{p}');\n"})
    u2, p2 = up()
    b = secrets({"a.php": f"<?php\n{WRAPPER}$c = call_user_func_array('open_db', ['{u2}', '{p2}']);\n"})
    assert a == {u, p} and b == {u2, p2}


def test_variable_function_name():
    u, p = up()
    assert secrets({"a.php": f"<?php\n{WRAPPER}$f = 'open_db';\n$f('{u}', '{p}');\n"}) == {u, p}


def test_method_and_constructor():
    u, p = up()
    text = ("<?php\nclass Db {\n  function __construct($u, $p) { $this->c = new PDO('mysql:host=db', $u, $p); }\n}\n"
            f"$db = new Db('{u}', '{p}');\n")
    assert secrets({"a.php": text}) == {u, p}


def test_method_call_on_object():
    u, p = up()
    text = ("<?php\nclass Db {\n  function open($u, $p) { return mysqli_connect('db', $u, $p); }\n}\n"
            f"$db = new Db();\n$db->open('{u}', '{p}');\nDb::open('{u}', '{p}');\n")
    assert secrets({"a.php": text}) == {u, p}


def test_parameter_default_literal():
    _, p = up()
    text = f"<?php\nfunction f($p = '{p}') {{ return mysqli_connect('db', 'app', $p); }}\n"
    assert secrets({"a.php": text}) == {p}


def test_function_names_case_insensitive():
    u, p = up()
    assert secrets({"a.php": f"<?php\n{WRAPPER}OPEN_DB('{u}', '{p}');\n"}) == {u, p}


def test_recursion_terminates():
    _, p = up()
    text = ("<?php\nfunction f($p) { return $GLOBALS['x'] ? f($p) : mysqli_connect('db', 'app', $p); }\n"
            f"f('{p}');\n")
    assert secrets({"a.php": text}) == {p}


def test_argument_through_caller_variable():
    u, p = up()
    text = f"<?php\n{WRAPPER}$user = '{u}';\n$pass = '{p}';\nopen_db($user, $pass);\n"
    assert secrets({"a.php": text}) == {u, p}


def test_dynamic_call_conservative():
    u, p = up()
    findings, warnings = trace_php({"a.php": f"<?php\n{WRAPPER}$fn = $_GET['f'];\n$fn('{u}', '{p}');\n"}, ast=True)
    assert {f.secret for f in findings} == {u, p}
    assert any(w.reason == "unresolved-dynamic-call" for w in warnings)


def test_no_sink_reaching_function_no_dynamic_reports():
    u, p = up()
    text = f"<?php\nfunction greet($a, $b) {{ echo $a . $b; }}\n$fn = $_GET['f'];\n$fn('{u}', '{p}');\n"
    assert trace_php({"a.php": text}, ast=True) == ([], [])


def test_unrelated_calls_not_reported():
    u, p = up()
    text = f"<?php\n{WRAPPER}log_line('{u}', '{p}');\n"
    assert secrets({"a.php": text}) == set()


# --- final review fixes -------------------------------------------------------

def test_ast_scaling_with_method_calls():
    """C1: method-call resolution and enclosing-function lookup must not be
    quadratic in the number of functions."""
    import time
    texts = {}
    for i in range(1000):
        methods = "".join(f"  function m{j}($a, $b) {{ return $a . $b; }}\n" for j in range(10))
        calls = "".join(f"$o->m{j % 10}('x{i}', 'y{j}');\n" for j in range(20))
        texts[f"c{i}.php"] = (f"<?php\nclass C{i} {{\n{methods}}}\n{calls}"
                              f"function w{i}($p) {{ return mysqli_connect('db', 'app', $p); }}\nw{i}('pw{i}x');\n")
    t0 = time.monotonic()
    findings, _ = trace_php(texts, ast=True)
    assert time.monotonic() - t0 < 5.0
    assert len(findings) == 1000


def test_duplicate_class_definitions_all_indexed():
    """I3: two copies of a class (admin/ and public/) must both be traced."""
    _, p = up()
    texts = {
        "admin/Db.php": "<?php\nclass Db {\n  function c($x) { return strlen($x); }\n}\n",
        "public/Db.php": "<?php\nclass Db {\n  function c($k) { return mysqli_connect('db', 'app', $k); }\n}\n",
        "index.php": f"<?php\n$d = new Db();\n$d->c('{p}');\n",
    }
    assert secrets(texts) == {p}


def test_deeply_nested_php_does_not_crash():
    """I5: the AST walk must not recurse per nesting level."""
    concat = "<?php\n$x = " + " . ".join(["'a'"] * 3000) + ";\n"
    arrays = "<?php\n$x = " + "[" * 1200 + "]" * 1200 + ";\n"
    elifs = "<?php\nif ($a) { $b = 1; }\n" + "".join(f"else if ($a == {i}) {{ $b = {i}; }}\n" for i in range(500))
    for text in (concat, arrays, elifs):
        trace_php({"a.php": text + WRAPPER}, ast=True)


def test_dynamic_policy_respects_arity_and_skips_new_variable():
    """I6: dynamic calls whose argument count cannot fit the target, and
    `new $cls(...)`, are not credentials."""
    a, b = up()
    text = (f"<?php\n{WRAPPER}$h = $_GET['h'];\n$h('{a}', '{b}', 'third', 'fourth');\n"
            f"$cls = $_GET['c'];\n$o = new $cls('{a}', '{b}');\n")
    assert secrets({"a.php": text}) == set()


def test_parent_and_literal_class_calls_resolve_exactly():
    """I6: parent::__construct and Other::open must not match Db's methods."""
    a, b = up()
    text = ("<?php\nclass Db {\n  function __construct($u, $p) { $this->c = new PDO('x', $u, $p); }\n"
            "  function open($u, $p) { return mysqli_connect('db', $u, $p); }\n}\n"
            f"class Form extends BaseForm {{\n  function __construct() {{ parent::__construct('{a}', '{b}'); }}\n}}\n"
            f"Other::open('{a}', '{b}');\n")
    assert secrets({"a.php": text}) == set()


def test_self_static_and_exact_class_calls_still_traced():
    u, p = up()
    text = ("<?php\nclass Db {\n  function open($u, $p) { return mysqli_connect('db', $u, $p); }\n"
            f"  function boot() {{ return self::open('{u}', '{p}'); }}\n}}\n")
    u2, p2 = up()
    text2 = f"<?php\nclass Db {{\n  static function open($u, $p) {{ return mysqli_connect('db', $u, $p); }}\n}}\nDb::open('{u2}', '{p2}');\n"
    assert secrets({"a.php": text}) == {u, p}
    assert secrets({"b.php": text2}) == {u2, p2}
