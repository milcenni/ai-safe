"""Phase B: PHP sink arguments traced to variables, constants, properties,
include files and globals. Values are synthetic and generated at runtime."""

import json
import random

from ai_safe.php_dataflow import FlowWarning, trace_php
from conftest import all_text, builtin_config, prepare, short_word

_R = random.Random(99)


def pw() -> str:
    return short_word(_R, 5) + "3"


def secrets(texts: dict[str, str]) -> set[str]:
    return {f.secret for f in trace_php(texts)[0]}


# --- Task 3: same file ------------------------------------------------------

def test_same_file_short_variable():
    p = pw()
    assert secrets({"a.php": f"<?php\n$pw = '{p}';\nmysqli_connect('db', 'app', $pw);\n"}) == {p}


def test_reassigned_variable_reports_all_literals():
    a, b = pw(), pw()
    text = f"<?php\n$pw = '{a}';\nif ($prod) {{ $pw = \"{b}\"; }}\n$c = mysqli_connect('db', 'app', $pw);\n"
    assert secrets({"a.php": text}) == {a, b}


def test_constant_any_name():
    a, b = pw(), pw()
    assert secrets({"a.php": f"<?php\ndefine('X1', '{a}');\nmysqli_connect('db', 'app', X1);\n"}) == {a}
    assert secrets({"a.php": f"<?php\nconst K = '{b}';\nnew PDO('mysql:host=db', 'app', K);\n"}) == {b}


def test_class_constant():
    p = pw()
    text = f"<?php\nclass Db {{\n  const P = '{p}';\n  function c() {{ return new mysqli('db', 'app', self::P); }}\n}}\n"
    assert secrets({"a.php": text}) == {p}


def test_class_property():
    a, b = pw(), pw()
    text = (f"<?php\nclass Db {{\n  var $k = '{a}';\n  private static $s = '{b}';\n"
            "  function c() { return new mysqli('db', 'app', $this->k); }\n"
            "  function d() { return new mysqli('db', 'app', self::$s); }\n}\n")
    assert secrets({"a.php": text}) == {a, b}


def test_username_traced_with_password():
    u, p = short_word(_R, 7), pw()
    text = f"<?php\n$u = '{u}';\n$p = '{p}';\nmysqli_connect('db', $u, $p);\n"
    found = {(f.role, f.secret) for f in trace_php({"a.php": text})[0]}
    assert found == {("user", u), ("password", p)}


def test_user_reported_only_with_password():
    u = short_word(_R, 7)
    assert secrets({"a.php": f"<?php\n$u = '{u}';\n$p = getenv('P');\nmysqli_connect('db', $u, $p);\n"}) == set()


def test_non_credential_sources_ignored():
    for src in ("$_POST['p']", "getenv('P')", "config('db.password')", "$_ENV['P']", "$_SERVER['P']"):
        text = f"<?php\n$p = {src};\nmysqli_connect('db', 'app', $p);\nmysqli_connect('db', 'app', {src});\n"
        assert trace_php({"a.php": text}) == ([], []), src


def test_host_and_dbname_slots_never_traced():
    h, d, p = "database01", "shopdata", pw()
    text = f"<?php\n$host = '{h}';\n$db = '{d}';\nmysqli_connect($host, 'app', '{p}', $db);\n"
    assert secrets({"a.php": text}) == set()  # the literal password is Stage 1's, host/db are never traced


def test_literal_slots_left_to_stage1():
    p = pw()
    assert secrets({"a.php": f"<?php\nmysqli_connect('db', 'app', '{p}');\n"}) == set()


def test_expression_argument_warns():
    findings, warnings = trace_php({"a.php": "<?php\n$c = mysqli_connect('db', 'app', $a . $b);\n"})
    assert findings == [] and warnings == [FlowWarning("a.php", 2, "expression")]


def test_dataflow_warnings_contain_no_values(make_repo):
    p1, p2 = pw(), pw()
    repo = make_repo({
        "a.php": f"<?php\n$pw = '{p1}';\n$c = mysqli_connect('db', 'app', $pw . '{p2}');\n",
    })
    p = prepare(repo, builtin_config())
    out = json.dumps(p.scan.public())
    assert any("php-dataflow: expression at a.php:3" in w for w in p.scan.warnings)
    assert p1 not in out and p2 not in out


def test_dataflow_findings_reach_sanitizer(make_repo):
    p1 = pw()
    p = prepare(make_repo({"a.php": f"<?php\n$pw = '{p1}';\nmysqli_connect('db', 'app', $pw);\n"}), builtin_config())
    assert p1 not in all_text(p.ws)
    assert p.verification.passed


def test_php_dataflow_off_disables_pass(make_repo):
    p1 = pw()
    cfg = builtin_config()
    cfg.scanner.php_dataflow = "off"
    p = prepare(make_repo({"a.php": f"<?php\n$pw = '{p1}';\nmysqli_connect('db', 'app', $pw);\n"}), cfg)
    assert p1 in all_text(p.ws)
