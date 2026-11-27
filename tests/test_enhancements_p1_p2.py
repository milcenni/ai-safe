"""P1/P2 gaps from the sanitizer gap analysis: key names, structural
patterns, provider prefixes, sibling usernames, identifiers, shared
placeholders and the independent verify checks. All values are synthetic and
generated at runtime."""

from __future__ import annotations

import random
import re
import string

import pytest

from conftest import all_text, builtin_config, prepare

from ai_safe.classifier import is_identifier_key, is_sensitive_key, is_user_key
from ai_safe.detectors import BuiltinDetector, looks_like_secret_value
from ai_safe.models import Category
from ai_safe.verifier import VerificationReport
from ai_safe.verify_checks import adjacency_issues, entropy_issues, prefix_issues, run_checks, url_issues

R = random.Random(2202)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(R.choice(alphabet) for _ in range(n))


def rand_mixed(n: int) -> str:
    """Random, with at least one digit and one letter."""
    return rand(n - 2) + R.choice(string.digits) + R.choice(string.ascii_letters)


def scan(text: str, path: str = "a.php", **kw):
    return BuiltinDetector(**kw).scan_text(text, path)


def secrets_of(text: str, path: str = "a.php", **kw) -> set[str]:
    return {m.secret for m in scan(text, path, **kw)}


# ---------------------------------------------------------------------------
# 2. Key names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["AWS_ACCESS_KEY_ID", "vault_secret_id", "client_secret_id", "STRIPE_KEY", "PUSHER_APP_KEY",
                                 "SENDGRID_KEY", "merchantKey", "fedexKey", "PAGERDUTY_ROUTING_KEY", "APP_KEY", "HASH_SALT",
                                 "app_pepper", "NEW_RELIC_LICENSE", "upsLicenseNumber", "webhook_signature", "hmac"])
def test_sensitive_key_names(key):
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["primary_key", "cache_key", "public_key", "sort_key", "foreign_key", "translation_key",
                                 "client_id", "kms_key_id", "salt_rounds", "key", "license_url"])
def test_structural_key_names_are_not_sensitive(key):
    assert not is_sensitive_key(key)


def test_weak_keys_need_a_random_looking_value():
    assert not looks_like_secret_value("MIT", "license", "config", True)
    assert not looks_like_secret_value("Apache-2.0", "license", "config", True)
    assert not looks_like_secret_value("GPL-3.0-or-later", "license", "config", True)
    assert not looks_like_secret_value("messages.welcome_title", "fooKey", "source", True)
    assert looks_like_secret_value(rand_mixed(36), "merchantKey", "source", True)


def test_aws_key_id_with_wrong_length_is_still_replaced_by_key_name(make_repo):
    kid = "AKIA" + rand(15, string.ascii_uppercase + string.digits)  # one short: no token rule
    p = prepare(make_repo({"docker-compose.yml": f"services:\n  a:\n    environment:\n      - AWS_ACCESS_KEY_ID={kid}\n"}))
    assert kid not in all_text(p.ws)


def test_provider_keys_and_salts_are_replaced(make_repo):
    values = {k: rand_mixed(32) for k in ("stripe", "merchant", "routing", "salt", "license")}
    p = prepare(make_repo({
        "docker-compose.yml": f"services:\n  a:\n    environment:\n      - STRIPE_KEY={values['stripe']}\n",
        "lib/Client.php": f"<?php\n$merchantKey = '{values['merchant']}';\n",
        "app/Config/Pager.php": f"<?php\nclass Pager {{ public const PAGERDUTY_ROUTING_KEY = '{values['routing']}'; }}\n",
        "incls/constants.php": f"<?php\ndefine('HASH_SALT', 'my_unique_salt_{values['salt']}');\n",
        "app/Config/Monitor.php": f"<?php\nclass M {{ public const NEW_RELIC_LICENSE = '{values['license']}'; }}\n",
    }))
    text = all_text(p.ws)
    for v in values.values():
        assert v not in text


def test_license_field_in_package_metadata_is_kept(make_repo):
    p = prepare(make_repo({"composer.json": '{"name": "acme/app", "license": "MIT", "version": "1.2.3"}\n'}))
    assert '"license": "MIT"' in (p.ws / "composer.json").read_text()


def test_sensitive_container_leaves(make_repo):
    paypal, other = rand_mixed(60), rand_mixed(40)
    hub = "pat-na1-" + "-".join(rand(n, HEX) for n in (8, 4, 4, 4, 12))
    p = prepare(make_repo({
        "app/Helpers/credentials_helper.php": (
            "<?php\nfunction get_api_key(string $service): ?string\n{\n"
            "    $keys = [\n"
            f"        'paypal'  => '{paypal}',\n"
            f"        'hubspot' => '{hub}',\n"
            "        'label'   => 'plain words here',\n"
            "    ];\n    return $keys[$service] ?? null;\n}\n"
            f"function get_partner_token() {{ return ['acme' => '{other}']; }}\n"),
        "config/services.yaml": f"api_keys:\n  paypal: {paypal}\n  region: us-east-1\n",
    }))
    text = all_text(p.ws)
    assert paypal not in text and hub not in text and other not in text
    assert "region: us-east-1" in (p.ws / "config/services.yaml").read_text()


def test_container_with_column_names_is_left_alone():
    assert not scan("<?php\n$keys = ['id', 'name', 'email', 'user_profile_settings'];\n")


# ---------------------------------------------------------------------------
# 3. Structural patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tmpl,path", [
    ("<?php\n$pass = getenv('DB_PASS') ?: '{v}';\n", "a.php"),
    ("<?php\n$pass = $_SERVER['DB_PASS'] ?? '{v}';\n", "a.php"),
    ("const pass = process.env.DB_PASSWORD || '{v}';\n", "a.js"),
    ("pw = os.environ.get('DB_PASSWORD') or '{v}'\n", "a.py"),
    ("services:\n  a:\n    environment:\n      - DB_PASS=${{DB_PASS:-{v}}}\n", "docker-compose.yml"),
])
def test_env_fallback_literals(tmpl, path):
    v = "Fb_" + rand_mixed(10) + "!"
    assert v in secrets_of(tmpl.format(v=v), path)


def test_env_fallback_with_unknown_key_through_dataflow(make_repo):
    v = "Fb_" + rand_mixed(10) + "!"
    p = prepare(make_repo({"db.php": f"<?php\n$x = getenv('APP_VALUE_1') ?: '{v}';\n$m = new \\mysqli('db', 'app', $x, 'shop');\n"}))
    assert v not in all_text(p.ws)


def test_concatenated_password_is_rewritten_as_one_literal(make_repo):
    parts = ["Inl_" + rand(3), "Pw_" + rand(3), rand(2, string.digits) + "!"]
    p = prepare(make_repo({"legacy.php": (
        "<?php\n$u = 'inline_' . 'user';\n"
        f"$p = '{parts[0]}' . '{parts[1]}' . '{parts[2]}';\n"
        "$conn = mysqli_connect('db', $u, $p, 'shop');\n")}))
    assert p.verification.passed, p.verification.issues
    out = (p.ws / "legacy.php").read_text()
    assert re.search(r"\$p = '\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}';", out), out
    for part in parts:
        assert part not in out


def test_conninfo_through_variable(make_repo):
    pw = "Pg_" + rand_mixed(8) + "!"
    p = prepare(make_repo({"pg.php": (
        f'<?php\n$connString = "host=pg-ssl.db.internal port=5432 dbname=app user=ssl_user password={pw} sslmode=require";\n'
        "$conn = pg_connect($connString);\n")}))
    assert pw not in all_text(p.ws)


@pytest.mark.parametrize("url", [
    lambda: f"https://discord.com/api/webhooks/{rand(18, string.digits)}/{rand(68, ALNUM + '_-')}",
    lambda: f"https://acme.webhook.office.com/webhookb2/{rand(40, ALNUM + '-@')}",
    lambda: f"https://hooks.zapier-like.io/hooks/catch/{rand(30, ALNUM)}/",
])
def test_webhook_urls(url):
    u = url()
    assert any(u.startswith(s) or s in u for s in secrets_of(f"<?php\n$x = ['webhook' => '{u}'];\n"))


# ---------------------------------------------------------------------------
# 4. Provider prefixes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    lambda: "AIzaSyD" + "x" * 31,
    lambda: "SG." + "x" * 56,
    lambda: "x" * 32 + "-us1",
    lambda: "sq0atp-" + "x" * 32,
    lambda: "EAAB" + rand(8) + "...(long fb token)..." + rand(6),
    lambda: "eyJhbGciOi" + rand(10) + "...(k8s token)...",
])
def test_provider_prefix_under_sensitive_key_skips_gates(value):
    v = value()
    assert looks_like_secret_value(v, "access_token", "source", True)


@pytest.mark.parametrize("rule,value", [
    ("stripe-webhook-secret", lambda: "whsec_" + rand(32)),
    ("square-access-token", lambda: "sq0atp-" + rand(22)),
    ("hubspot-private-app", lambda: "pat-eu1-" + "-".join(rand(n, HEX) for n in (8, 4, 4, 4, 12))),
    ("mailchimp-api-key", lambda: rand(32, HEX) + "-us12"),
    ("google-oauth-client-secret", lambda: "GOCSPX-" + rand(28)),
    ("digitalocean-token", lambda: "dop_v1_" + rand(64, HEX)),
    ("planetscale-token", lambda: "pscale_pw_" + rand(40)),
    ("supabase-management-token", lambda: "sbp_" + rand(40, HEX)),
    ("shopify-token", lambda: "shpat_" + rand(32, HEX)),
    ("vault-token", lambda: "hvs." + rand(30)),
    ("doppler-token", lambda: "dp.st." + rand(44)),
    ("postman-api-key", lambda: "PMAK-" + rand(24, HEX) + "-" + rand(34, HEX)),
    ("newrelic-key", lambda: "NRAK-" + rand(27, string.ascii_uppercase + string.digits)),
    ("sentry-auth-token", lambda: "sntrys_" + rand(48)),
    ("age-secret-key", lambda: "AGE-SECRET-KEY-1" + rand(58, string.ascii_uppercase + string.digits)),
    ("telegram-bot-token", lambda: rand(9, string.digits) + ":" + rand(35)),
])
def test_provider_token_rules(rule, value):
    v = value()
    hits = [m for m in scan(f"<?php\n$cfg = ['x' => '{v}'];\n") if m.secret == v]
    assert hits, rule


# ---------------------------------------------------------------------------
# 5. Usernames next to passwords
# ---------------------------------------------------------------------------

def test_sibling_usernames(make_repo):
    users = {"u1": "primary_" + rand(4).lower(), "u2": "mongo_" + rand(4).lower(), "u3": "rabbit_" + rand(4).lower(),
             "u4": "production_" + rand(4).lower()}
    p = prepare(make_repo({
        "app/Controllers/DatabaseController.php": (
            "<?php\n$connections = [\n"
            f"    'primary' => ['host' => 'db', 'user' => '{users['u1']}', 'pass' => '{rand_mixed(14)}'],\n];\n"),
        "docker-compose.yml": (
            "services:\n  db:\n    environment:\n"
            f"      - MONGO_INITDB_ROOT_USERNAME={users['u2']}\n      - MONGO_INITDB_ROOT_PASSWORD={rand_mixed(14)}\n"
            f"      - RABBITMQ_DEFAULT_USER={users['u3']}\n      - RABBITMQ_DEFAULT_PASS={rand_mixed(14)}\n"),
        "app/Config/Constants.php": (
            f"<?php\ndefined('DB_USER') || define('DB_USER', '{users['u4']}');\n"
            f"defined('DB_PASS') || define('DB_PASS', '{rand_mixed(14)}');\n"),
    }))
    assert p.verification.passed, p.verification.issues
    text = all_text(p.ws)
    for u in users.values():
        assert u not in text, u
    doc = (p.ws / "AI_SAFE_PLACEHOLDERS.md").read_text()
    assert "## User names" in doc


def test_default_usernames_are_kept_unless_configured():
    text = "<?php\n$cfg = ['user' => 'root', 'password' => '" + rand_mixed(14) + "'];\n"
    assert "root" not in secrets_of(text)
    from ai_safe.config import UsernameConfig
    assert "root" in secrets_of(text, usernames=UsernameConfig(include_default_usernames=True))


def test_user_without_secret_is_not_sanitized():
    assert not scan("<?php\n$cfg = ['user' => 'svc_reporting', 'timeout' => 30];\n")


def test_user_keys():
    for k in ("user", "DB_USERNAME", "MONGO_INITDB_ROOT_USERNAME", "RABBITMQ_DEFAULT_USER", "bind_dn", "dbuser", "login"):
        assert is_user_key(k), k
    assert not is_user_key("user_agent")


# ---------------------------------------------------------------------------
# 6. Identifiers
# ---------------------------------------------------------------------------

def test_identifiers(make_repo):
    vals = {
        "pk": "pk_live_" + rand(24), "sid": "AC" + rand(32, HEX), "msg": "MG" + rand(32, HEX),
        "tenant": "-".join(rand(n, HEX) for n in (8, 4, 4, 4, 12)), "client": rand_mixed(20),
        "phone": "+1415" + rand(7, string.digits), "account": rand(12, string.digits),
    }
    p = prepare(make_repo({"app/Config/Services.php": (
        "<?php\nreturn [\n"
        f"  'stripe' => ['public_key' => '{vals['pk']}'],\n"
        f"  'twilio' => ['account_sid' => '{vals['sid']}', 'phone_number' => '{vals['phone']}', 'messaging_service_sid' => '{vals['msg']}'],\n"
        f"  'azure'  => ['tenant_id' => '{vals['tenant']}', 'client_id' => '{vals['client']}'],\n"
        f"  'aws'    => ['kms_key_id' => 'arn:aws:kms:us-east-1:{vals['account']}:key/abc'],\n"
        "];\n")}))
    assert p.verification.passed, p.verification.issues
    text = all_text(p.ws)
    for v in vals.values():
        assert v not in text, v
    doc = (p.ws / "AI_SAFE_PLACEHOLDERS.md").read_text()
    assert "## Identifiers" in doc


def test_identifiers_can_be_disabled(make_repo):
    sid = "AC" + rand(32, HEX)
    cfg = builtin_config()
    cfg.sanitization.identifiers.enabled = False
    p = prepare(make_repo({"a.php": f"<?php\n$t = ['account_sid' => '{sid}'];\n"}), cfg)
    assert sid in all_text(p.ws)


def test_identifier_keys():
    assert is_identifier_key("azure_tenant_id") and is_identifier_key("smsAccountSid")
    assert not is_identifier_key("user_id_column")


def test_identifiers_are_not_propagated(make_repo):
    client = rand_mixed(16)
    p = prepare(make_repo({
        "a.php": f"<?php\n$cfg = ['client_id' => '{client}'];\n",
        "b.txt": f"build-{client}-artifact\n",
    }))
    assert f"build-{client}-artifact" in (p.ws / "b.txt").read_text()


# ---------------------------------------------------------------------------
# 8. Shared placeholders and reuse warnings
# ---------------------------------------------------------------------------

def test_reused_value_gets_shared_placeholder(make_repo):
    v = rand_mixed(32)
    p = prepare(make_repo({
        "app/Config/Services.php": (
            "<?php\nreturn [\n"
            f"  'twilio' => ['auth_token' => '{v}'],\n"
            f"  'datadog' => ['api_key' => '{v}'],\n];\n"),
        "config/services.yaml": f"facebook:\n  app_secret: {v}\n",
    }))
    text = (p.ws / "app/Config/Services.php").read_text()
    assert re.search(r"\$\{AI_SAFE_SECRET_SHARED_[A-Z_]+_[0-9A-F]{6}\}", text), text
    assert "TWILIO" not in text and "DATADOG" not in text
    assert any("credential reuse" in w and "auth_token" in w and "api_key" in w for w in p.scan.warnings)
    doc = (p.ws / "AI_SAFE_PLACEHOLDERS.md").read_text()
    assert "SHARED_" in doc and "auth_token" in doc.lower().replace("_", "_")


def test_same_value_same_key_is_not_shared(make_repo):
    v = rand_mixed(20)
    p = prepare(make_repo({"a.php": f"<?php\n$db_password = '{v}';\n", "b.php": f"<?php\n$db_password = '{v}';\n"}))
    assert "${AI_SAFE_SECRET_DB_PASSWORD}" in (p.ws / "a.php").read_text()
    assert not any("credential reuse" in w for w in p.scan.warnings)


# ---------------------------------------------------------------------------
# 9. Independent verify checks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "x = '${AI_SAFE_SECRET_A}Zz9Yy8Xx7Ww6='", "x = '${AI_SAFE_SECRET_A}MNO678'", "u = 'prod_${AI_SAFE_SECRET_A}'",
    "h = '${AI_SAFE_SECRET_A}-server.company.internal'", "h = '$2y$10$${AI_SAFE_SECRET_A}rstu.salt.hash'",
])
def test_adjacency_detects_partial_replacement(bad):
    assert adjacency_issues(bad)


@pytest.mark.parametrize("good", [
    "K=base64:${AI_SAFE_SECRET_A}", "h: Bearer ${AI_SAFE_SECRET_A}", "a=${AI_SAFE_SECRET_A};b",
    "p = '$2y$10$${AI_SAFE_SECRET_A}'", "u = 'https://api.telegram.org/bot${AI_SAFE_SECRET_A}/send'",
    "mysql -p${AI_SAFE_SECRET_A} db", "u = 'redis://:${AI_SAFE_SECRET_A}@${AI_SAFE_HOST_B}:6379/0'",
    "s = 'The value is ${AI_SAFE_SECRET_A}.'",
])
def test_adjacency_allows_known_forms(good):
    assert not adjacency_issues(good)


def test_adjacency_allows_kept_provider_suffix():
    assert not adjacency_issues("h = '${AI_SAFE_HOST_1A2B3C}.rds.amazonaws.com'", (".rds.amazonaws.com",))
    assert adjacency_issues("h = '${AI_SAFE_HOST_1A2B3C}.corp-x.net'", (".rds.amazonaws.com",))


def test_url_reparse():
    assert url_issues("u = 'mongodb://admin:${AI_SAFE_SECRET_A}@ss_99!@mongo.x.net:27017/db'")
    assert not url_issues("u = 'mongodb://admin:${AI_SAFE_SECRET_A}@mongo.x.net:27017/db'")
    assert not url_issues("u = 'mongodb://${AI_SAFE_SECRET_U}:${AI_SAFE_SECRET_A}@${AI_SAFE_HOST_H}/db'")


def test_prefix_sweep_and_entropy_sweep():
    assert prefix_issues("t = 'ghp_" + rand(30) + "1'")
    assert not prefix_issues("t = '${AI_SAFE_SECRET_GH}'")
    assert entropy_issues("x = '" + rand_mixed(32) + "'\n", "a.php")
    assert not entropy_issues("x = '" + rand(32, HEX) + "'\n", "a.php")          # hash constant
    assert not entropy_issues("x = '" + rand_mixed(32) + "'\n", "package-lock.json")


def test_run_checks_reports_without_values():
    v = rand_mixed(10)
    rep = VerificationReport(workspace="w")
    run_checks(rep, f"x = '${{AI_SAFE_SECRET_A}}{v}'\n", "a.php")
    assert rep.issues and all(v not in i.message for i in rep.issues)
    assert not rep.passed


def test_verify_reports_engines(make_repo):
    p = prepare(make_repo({"README.md": "# x\n"}))
    assert any(i.code == "engines" for i in p.verification.issues)
    manifest = p.session.manifest_path.read_text()
    assert '"engines"' in manifest
    assert "builtin only" in (p.ws / "AI_SAFE_PLACEHOLDERS.md").read_text()


def test_category_of_user_slots_is_username():
    found = scan("<?php\n$c = mysqli_connect('db', 'svc_" + rand(5).lower() + "', '" + rand_mixed(14) + "');\n")
    assert {m.category for m in found} == {Category.USERNAME, Category.DATABASE_CREDENTIAL}
