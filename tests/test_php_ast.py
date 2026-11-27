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
