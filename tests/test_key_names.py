"""Compound password key names common in legacy code ($dbpass, $smtppwd)."""

import random

import pytest

from ai_safe.classifier import is_password_key, is_sensitive_key, split_compound_password
from ai_safe.detectors import BuiltinDetector
from conftest import short_word


@pytest.mark.parametrize("key", ["dbpass", "DBPASS", "dbpwd", "mysqlpassword", "smtppass", "ftppw", "adminpasswd"])
def test_compound_password_keys_are_password_keys(key):
    assert is_sensitive_key(key) and is_password_key(key)


@pytest.mark.parametrize("key", ["bypass", "compass", "surpass", "passthrough", "trespass", "dbpath", "apipassthrough"])
def test_ordinary_words_are_not_password_keys(key):
    assert not is_password_key(key)
    assert not split_compound_password(key.lower())


def test_compound_var_detected_in_php():
    v = "Zq" + short_word(random.Random(1), 6)
    assert [m.secret for m in BuiltinDetector().scan_text(f"<?php\n$dbpass = '{v}';\n", "c.php")] == [v]


def test_short_compound_password_detected():
    v = short_word(random.Random(2), 4)
    assert [m.secret for m in BuiltinDetector().scan_text(f"<?php\n$dbpwd = '{v}';\n", "c.php")] == [v]
