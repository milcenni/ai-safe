"""P0 regressions from the sanitizer gap analysis: partial replacement and
over-replacement. Every credential is synthetic and generated at runtime."""

from __future__ import annotations

import random
import re
import string

import pytest

from conftest import all_text, builtin_config, prepare

from ai_safe.config import AISafeConfig
from ai_safe.detectors import BuiltinDetector, accept_engine_finding, looks_like_regex_or_code
from ai_safe.models import Location
from ai_safe.scanner import Scanner

R = random.Random(1101)
PH = re.compile(r"\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}")


def _no_infra():
    cfg = builtin_config()
    cfg.sanitization.infrastructure.enabled = False  # isolate the username behaviour
    return cfg


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(R.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# 1.1 URL userinfo password containing '@'
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("special", ["@", "!@", "@:#", "%40@", "@@"])
def test_url_password_with_at_is_replaced_whole(make_repo, special):
    pw = rand(5) + special + rand(6) + "!"
    host = "mongo-" + rand(6).lower() + ".corp-net.org"
    uri = f"mongodb://admin:{pw}@{host}:27017/app?authSource=admin"
    p = prepare(make_repo({
        "app/Config/Connections.php": f"<?php\nclass Connections {{\n    public const MONGODB_URI = '{uri}';\n}}\n",
        "config/database.json": '{\n  "mongo": {"uri": "' + uri + '"}\n}\n',
        "config/services.yaml": f"mongo:\n  uri: {uri}\n",
        "deploy/app.env": f"MONGO_URL={uri}\n",
    }))
    assert p.verification.passed, p.verification.issues
    text = all_text(p.ws)
    assert pw not in text
    for fragment in (pw.split("@")[-1], pw.split("@")[0]):
        if len(fragment) >= 4:
            assert fragment not in text
    php = (p.ws / "app/Config/Connections.php").read_text()
    host_re = "(?:" + re.escape(host) + r"|\$\{AI_SAFE_HOST_[A-Z0-9_]+\})"  # the host may be an infrastructure placeholder
    assert re.search(r"mongodb://admin:\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}@" + host_re + ":27017/app", php), php


def test_url_without_password_is_not_matched():
    d = BuiltinDetector()
    assert not [m for m in d.scan_text("u = 'https://h.example.net:8080/x?mail=a@b.example.com'", "a.php")
                if m.rule_id == "url-credentials"]


# ---------------------------------------------------------------------------
# 1.2 Propagation inside a larger token: no fragment of the parent leaks
# ---------------------------------------------------------------------------

def test_propagated_secret_inside_larger_token_replaces_whole_token(make_repo):
    child = rand(32)
    tail = rand(12)
    p = prepare(make_repo({
        "app/Config/Services.php": f"<?php\nreturn ['oauth_secret' => '{child}'];\n",
        "docker-compose.yml": f"services:\n  app:\n    environment:\n      - SESSION_BLOB=base64:{child}{tail}=\n",
        "app/Config/Maps.php": f"<?php\nreturn ['google_maps' => '{child}{tail[:6]}'];\n",
    }))
    assert p.verification.passed, p.verification.issues
    compose = (p.ws / "docker-compose.yml").read_text()
    assert "SESSION_BLOB=base64:${AI_SAFE_SECRET_SESSION_BLOB}\n" in compose, compose
    text = all_text(p.ws)
    assert child not in text and tail not in text and tail[:6] not in text
    maps = (p.ws / "app/Config/Maps.php").read_text()
    assert re.search(r"'google_maps' => '\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}'", maps), maps


def test_detected_value_keeps_format_prefix(make_repo):
    key = rand(43) + "="
    p = prepare(make_repo({"docker-compose.yml": f"services:\n  app:\n    environment:\n      - APP_KEY=base64:{key}\n"}))
    compose = (p.ws / "docker-compose.yml").read_text()
    assert "APP_KEY=base64:${AI_SAFE_SECRET_APP_KEY}\n" in compose, compose


def test_password_hash_is_replaced_whole(make_repo):
    body = rand(53, string.ascii_letters + string.digits + "./")
    p = prepare(make_repo({"seed.php": f"<?php\n$users = [['name' => 'ops', 'hash' => '$2y$10${body}']];\n"}))
    out = (p.ws / "seed.php").read_text()
    assert body not in out and body[-10:] not in out
    assert PH.search(out)


# ---------------------------------------------------------------------------
# 1.3 No over-replacement of text that merely contains a username
# ---------------------------------------------------------------------------

def test_username_is_not_replaced_inside_other_identifiers(make_repo):
    user = "svc" + rand(5, string.ascii_lowercase + string.digits)
    pw = "Pw-" + rand(14)
    p = prepare(make_repo({
        "db.php": f"<?php\n$c = mysqli_connect('db', '{user}', '{pw}');\n",
        "config/database.json": '{"username": "prod_' + user + '", "replica": "' + user + '-server.corp.internal"}\n',
        "ftp.php": f"<?php\n$host = '{user}-server.corp.internal';\n",
    }), _no_infra())
    assert p.verification.passed, p.verification.issues
    db = (p.ws / "db.php").read_text()
    assert user not in db and pw not in db
    js = (p.ws / "config/database.json").read_text()
    assert f'"prod_{user}"' in js and f'"{user}-server.corp.internal"' in js
    assert f"'{user}-server.corp.internal'" in (p.ws / "ftp.php").read_text()


def test_low_entropy_password_is_replaced_as_whole_token_only(make_repo):
    pw = "abcabc" + "12"
    p = prepare(make_repo({
        "a.php": f"<?php\n$db_password = '{pw}';\n",
        "b.php": f"<?php\n$other = '{pw}';\n$label = 'x{pw}y';\n",
    }))
    b = (p.ws / "b.php").read_text()
    assert f"'{pw}'" not in b          # whole-token copy: replaced
    assert f"'x{pw}y'" in b            # inside another word: left alone


# ---------------------------------------------------------------------------
# 1.4 Comment rule keeps closing punctuation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("close", [")", ").", "]", ","])
def test_comment_secret_keeps_closing_punctuation(close):
    pw = "Adm1n_" + rand(6)
    d = BuiltinDetector()
    line = f"-- Insert default admin user (password: {pw}{close}\n"
    hits = [m for m in d.scan_text(line, "x.sql") if m.rule_id == "comment-secret"]
    assert [m.secret for m in hits] == [pw]


# ---------------------------------------------------------------------------
# 1.5 Gitleaks generic findings: regexes and code are not secrets
# ---------------------------------------------------------------------------

def test_regex_is_not_a_secret():
    assert looks_like_regex_or_code(">[A-Za-z0-9]{32})")
    assert looks_like_regex_or_code(r"(?P<secret>\d{6})")
    assert not looks_like_regex_or_code(rand(32))
    assert not accept_engine_finding("generic-api-key", ">[A-Za-z0-9]{32})", "secret", "ai-safe.yaml")
    assert accept_engine_finding("generic-api-key", rand(24), "api_key", "config/app.yaml")
    assert accept_engine_finding("stripe-access-token", "sk_live_" + rand(24), None, "a.php")


def test_gitleaks_generic_regex_record_is_dropped(tmp_path):
    cfg = AISafeConfig()
    cfg.scanner.engine = "builtin"
    sc = Scanner(cfg, b"s" * 32)
    rec = {"RuleID": "generic-api-key", "Secret": ">[A-Za-z0-9]{32})", "File": "ai-safe.yaml", "StartLine": 3,
           "Match": 'regex: "isvc_(?P<secret>[A-Za-z0-9]{32})"'}
    assert sc.from_gitleaks(rec, Location.TRACKED) is None
    rec2 = dict(rec, Secret=rand(28), Match="api_key: " + "x")
    assert sc.from_gitleaks(rec2, Location.TRACKED) is not None


def test_default_config_regex_example_survives_sanitization(make_repo):
    from ai_safe.config import DEFAULT_CONFIG_YAML

    p = prepare(make_repo({"ai-safe.yaml": DEFAULT_CONFIG_YAML.replace("engine: gitleaks", "engine: builtin")}))
    out = (p.ws / "ai-safe.yaml").read_text()
    assert 'regex: "isvc_(?P<secret>[A-Za-z0-9]{32})"' in out
