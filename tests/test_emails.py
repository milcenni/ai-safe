"""Email addresses (internal staff, customers) are detected and sanitized by
default; ``sanitization.sanitize_emails: false`` turns this off. Addresses
are generated at runtime."""

import random
import string

import pytest

from ai_safe.config import AISafeConfig
from ai_safe.detectors import BuiltinDetector
from ai_safe.models import Category
from ai_safe.review import review_session
from conftest import all_text, builtin_config, prepare, write

_R = random.Random(7)


def email(domain: str | None = None) -> str:
    local = "".join(_R.choice(string.ascii_lowercase) for _ in range(6))
    dom = domain or "".join(_R.choice(string.ascii_lowercase) for _ in range(5)) + ".com"
    return f"{local}@{dom}"


def found(text: str, path: str = "a.php", **kw) -> list[str]:
    return [m.secret for m in BuiltinDetector(**kw).scan_text(text, path)]


FORMS = {
    "php-comma-string": lambda a, b: f"<?php\n$variable = '{a}, {b}';\n",
    "php-array": lambda a, b: f"<?php\n$list = ['{a}' ,'{b}'];\n",
    "php-long-array": lambda a, b: f'<?php\n$list = array("{a}", "{b}");\n',
    "python": lambda a, b: f'ADMINS = ["{a}", "{b}"]\n',
    "yaml": lambda a, b: f"notify:\n  - {a}\n  - {b}\n",
    "env-like": lambda a, b: f"MAIL_FROM={a}\nMAIL_TO=<{b}>\n",
    "html-mailto": lambda a, b: f'<a href="mailto:{a}">x</a> <p>{b}</p>\n',
    "sql-seed": lambda a, b: f"INSERT INTO users (email) VALUES ('{a}'), ('{b}');\n",
    "subdomain-plus": lambda a, b: f"$x = '{a.replace('@', '+tag@mail.')}'; $y = '{b}';\n",
}


@pytest.mark.parametrize("name", sorted(FORMS))
def test_emails_detected(name):
    a, b = email(), email()
    text = FORMS[name](a, b)
    secrets = found(text, "f.php" if "php" in name else "f.txt")
    a_expected = a.replace("@", "+tag@mail.") if name == "subdomain-plus" else a
    assert a_expected in secrets and b in secrets, (name, secrets)


def test_email_category():
    m = BuiltinDetector().scan_text(f"$x = '{email()}';\n", "a.php")
    assert [x.category for x in m] == [Category.EMAIL]


NOT_EMAILS = [
    "git remote add origin git@github.com:org/repo.git\n",
    '"url": "git@gitlab.internal:team/app.git"\n',
    "<img src=\"logo@2x.png\"> <img src='icon@3x.webp'>\n",
    '"dependencies": {"left-pad@1.3.0": "x", "@types/node": "^20"}\n',
    "import pkg from '@babel/core';\n",
    "@app.route('/x')\ndef x(): pass\n",
    "contact = 'someone@example.com'  # documentation domain\n",
    "a = 'ops@example.org'; b = 'x@example.net'; c = 'y@shop.example'\n",
    "a = 'u@host.test'; b = 'u@mail.invalid'; c = 'u@app.localhost'\n",
    "url = 'https://user@cdn.company.com/path'\n",
    "$p = '${AI_SAFE_SECRET_EMAIL_ABC123}';\n",
    "Ciphers chacha20-poly1305@openssh.com\nKexAlgorithms curve25519-sha256@libssh.org\n",
]


@pytest.mark.parametrize("text", NOT_EMAILS)
def test_not_emails(text):
    assert found(text, "f.txt") == []


def test_url_password_keeps_its_own_rule():
    pw = "Pw" + "".join(_R.choice(string.ascii_letters) for _ in range(12))
    m = BuiltinDetector().scan_text(f"DB = 'mysql://app:{pw}@db.company.com/app'\n", "a.py")
    assert [(x.rule_id, x.secret) for x in m] == [("url-credentials", pw)]


def test_emails_disabled_in_detector():
    assert found(f"$x = '{email()}';\n", emails=False) == []


def test_emails_sanitized_by_default(make_repo):
    a, b, c = email(), email(), email("corp.internal.com")
    p = prepare(make_repo({
        "app/config.php": f"<?php\n$variable = '{a}, {b}';\n",
        "app/list.php": f"<?php\n$list = ['{a}', '{c}'];\n",
        "README.md": f"Contact {c} for access.\n",
    }))
    text = all_text(p.ws)
    assert a not in text and b not in text and c not in text
    assert "AI_SAFE_SECRET_" in text
    assert p.verification.passed


def test_emails_not_sanitized_when_disabled(make_repo):
    a = email()
    cfg = builtin_config()
    cfg.sanitization.sanitize_emails = False
    p = prepare(make_repo({"app/config.php": f"<?php\n$variable = '{a}';\n"}), cfg)
    assert a in all_text(p.ws)
    assert p.verification.passed


def test_config_default_and_yaml_toggle():
    assert AISafeConfig().sanitization.sanitize_emails is True
    cfg = AISafeConfig.model_validate({"sanitization": {"sanitize_emails": False}})
    assert cfg.sanitization.sanitize_emails is False


def test_commit_message_emails_not_reported(make_repo):
    from conftest import git
    repo = make_repo({"a.txt": "x\n"})
    write(repo, {"b.txt": "y\n"})
    git(repo, "add", "b.txt")
    git(repo, "commit", "-q", "-m", f"change\n\nCo-Authored-By: Bot <{email()}>")
    p = prepare(repo)
    assert not [f for f in p.scan.findings if f.category is Category.EMAIL]


def test_ai_added_email_is_warning_not_blocking(make_repo):
    p = prepare(make_repo({"app/a.php": "<?php\n$x = 1;\n"}))
    write(p.ws, {"app/a.php": f"<?php\n$x = 1;\n$support = '{email()}';\n"})
    rr = review_session(p.session, p.cfg, p.scanner)
    issues = [(i.code, i.severity.blocking) for i in rr.issues if i.path == "app/a.php"]
    assert ("email-introduced", False) in issues
    assert rr.passed
