"""Legacy-PHP benchmark: how credentials are typically written in legacy PHP
projects. Templates are filled at runtime with synthetic values (``{PW}``,
``{USER}``; literal braces are doubled). ``weight`` estimates how common a
pattern is (total 100); adjust it from real samples. ``phase`` names the
work that makes the pattern pass: stage1 (already shipped), A, B, B1, C, D.
No template may contain an email address: email sanitization is on by
default and would hide what the benchmark measures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    files: dict[str, str]
    weight: int
    phase: str


PATTERNS: list[Pattern] = [
    Pattern("literal-in-sink", {"db.php": "<?php\n$c = mysql_connect('localhost', '{USER}', '{PW}');\n"}, 15, "stage1"),
    Pattern("define-constant", {"config.php": "<?php\ndefine('DB_PASS', '{PW}');\n"}, 10, "stage1"),
    Pattern("config-array-index", {"config.php": "<?php\n$config['db']['password'] = '{PW}';\n"}, 8, "stage1"),
    Pattern("named-var-config", {"config.php": "<?php\n$db_password = '{PW}';\n"}, 7, "stage1"),
    Pattern("compound-var-name", {"config.php": "<?php\n$dbhost = 'localhost';\n$dbpass = '{PW}';\n"}, 8, "A"),
    Pattern("short-var-same-file", {"db.php": "<?php\n$pw = '{PW}';\n$c = mysqli_connect('db', '{USER}', $pw);\n"}, 8, "B1"),
    Pattern("include-config-vars", {
        "config.php": "<?php\n$u = '{USER}';\n$p = '{PW}';\n",
        "db.php": "<?php\nrequire 'config.php';\n$c = mysqli_connect('db', $u, $p);\n",
    }, 12, "B"),
    Pattern("sibling-include", {
        "index.php": "<?php\ninclude 'config.php';\ninclude 'lib/db.php';\n",
        "config.php": "<?php\n$p = '{PW}';\n",
        "lib/db.php": "<?php\n$c = mysqli_connect('db', 'app', $p);\n",
    }, 6, "B"),
    Pattern("global-in-function", {
        "db.php": "<?php\n$p = '{PW}';\nfunction db() {{\n    global $p;\n    return mysqli_connect('db', 'app', $p);\n}}\n",
    }, 5, "B"),
    Pattern("odd-constant-name", {"db.php": "<?php\ndefine('X1', '{PW}');\n$c = mysqli_connect('db', 'app', X1);\n"}, 3, "B1"),
    Pattern("class-property", {
        "Db.php": "<?php\nclass Db {{\n    var $k = '{PW}';\n    function c() {{ return new mysqli('db', 'app', $this->k); }}\n}}\n",
    }, 4, "B1"),
    Pattern("wrapper-function", {
        "db.php": "<?php\nfunction open_db($u, $p) {{ return mysqli_connect('db', $u, $p); }}\nopen_db('{USER}', '{PW}');\n",
    }, 6, "C"),
    Pattern("wrapper-cross-file", {
        "lib.php": "<?php\nfunction open_db($u, $p) {{ return mysqli_connect('db', $u, $p); }}\n",
        "index.php": "<?php\nrequire 'lib.php';\n$c = open_db('{USER}', '{PW}');\n",
    }, 3, "C"),
    Pattern("call-user-func", {
        "db.php": "<?php\nfunction open_db($u, $p) {{ return mysqli_connect('db', $u, $p); }}\n$c = call_user_func('open_db', '{USER}', '{PW}');\n",
    }, 2, "C"),
    Pattern("sql-dump", {"dump.sql": "CREATE USER 'app'@'%' IDENTIFIED BY '{PW}';\n"}, 3, "D"),
]

assert sum(p.weight for p in PATTERNS) == 100

# Must produce zero findings: ordinary legacy code around the sinks.
NOT_SECRETS: dict[str, str] = {
    "names.php": "<?php\n$bypass = 'north-east-7';\n$compass = 'south';\n",
    "host.php": "<?php\n$host = 'database01';\n$u = 'appuser';\n$c = mysqli_connect($host, $u, getenv('P'));\n",
    "dbname.php": "<?php\n$dbname = 'shop_prod';\n",
    "post.php": "<?php\n$pw = $_POST['pw'];\n$c = mysqli_connect('db', 'app', $pw);\n",
    "env.php": "<?php\n$pw = getenv('DB_PASS');\n$c = mysqli_connect('db', 'app', $pw);\n",
    "dyn.php": "<?php\ninclude $path;\n",
    "ldap.php": "<?php\nldap_bind($ds);\n",
}
