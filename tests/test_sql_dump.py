"""Passwords in SQL dumps and migration scripts. Values are synthetic."""

import random
import string

import pytest

from ai_safe.detectors import BuiltinDetector
from conftest import short_word

_R = random.Random(11)


def found(text: str) -> list[str]:
    return [m.secret for m in BuiltinDetector().scan_text(text, "dump.sql")]


FORMS = [
    "CREATE USER 'app'@'%' IDENTIFIED BY '{p}';\n",
    "GRANT ALL ON *.* TO 'u'@'%' IDENTIFIED BY '{p}';\n",
    "ALTER USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password BY '{p}';\n",
    "SET PASSWORD FOR 'u'@'%' = '{p}';\n",
    "SET PASSWORD = PASSWORD('{p}');\n",
    "create user app identified by \"{p}\";\n",
]


@pytest.mark.parametrize("form", FORMS)
def test_sql_passwords_detected(form):
    p = short_word(_R, 5) + "8"
    assert p in found(form.format(p=p))


def test_hashed_and_placeholder_values_ignored():
    digest = "*" + "".join(_R.choice("0123456789ABCDEF") for _ in range(40))
    assert found(f"CREATE USER 'u'@'%' IDENTIFIED BY PASSWORD '{digest}';\n") == []
    assert found("-- CREATE USER 'u'@'%' IDENTIFIED BY 'your_password';\n") == []
    assert found("CREATE USER 'u'@'%' IDENTIFIED BY '${AI_SAFE_SECRET_DB_PASSWORD}';\n") == []


def test_password_method_calls_are_not_sql():
    """I4: form-builder password() calls must not be treated as SQL PASSWORD()."""
    for text in ("{!! Form::password('password_confirmation') !!}\n",
                 "<?php\n$form->password('user_password');\n",
                 "field.password('new_password_field');\n"):
        assert found(text) == [], text
