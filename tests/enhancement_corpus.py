"""Benchmark corpus for the sanitizer gap analysis (CodeIgniter-style PHP
project, configs, compose files). Templates are filled at runtime with
synthetic values: ``{name}`` refers to an entry of ``VALUES``; literal braces
are doubled. Every value is tagged with the category it measures:

* ``secret``     - must never reach the workspace
* ``username``   - a user name next to a credential
* ``identifier`` - account / tenant / client IDs
* ``host``       - internal host names and private IP addresses
* ``keep``       - must reach the workspace unchanged (false-positive guard)

No real credential, host or organisation appears here."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Callable

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def _s(r: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def _mixed(r: random.Random, n: int) -> str:
    return _s(r, n - 2) + r.choice(string.digits) + r.choice(string.ascii_letters)


@dataclass(frozen=True)
class Value:
    category: str
    make: Callable[[random.Random], str]


ORG = "corp-bench.net"

VALUES: dict[str, Value] = {
    # secrets
    "mongo_pw": Value("secret", lambda r: "Mg0_" + _s(r, 5) + "@" + _s(r, 6) + "!"),
    "redis_pw": Value("secret", lambda r: "Rd5_" + _s(r, 4) + "@" + _s(r, 5)),
    "oauth": Value("secret", lambda r: _mixed(r, 32)),
    "app_tail": Value("secret", lambda r: _mixed(r, 12)),
    "db_pw": Value("secret", lambda r: "Pw-" + _mixed(r, 14)),
    "comment_pw": Value("secret", lambda r: "Adm1n_" + _mixed(r, 6)),
    "aws_id": Value("secret", lambda r: "AKIA" + _s(r, 16, string.ascii_uppercase + "234567")),
    "aws_secret": Value("secret", lambda r: _s(r, 40, ALNUM + "+/")),
    "stripe": Value("secret", lambda r: "sk_live_" + _s(r, 24)),
    "merchant": Value("secret", lambda r: _mixed(r, 36)),
    "routing": Value("secret", lambda r: _mixed(r, 32)),
    "salt": Value("secret", lambda r: _mixed(r, 20)),
    "license": Value("secret", lambda r: _s(r, 36, HEX) + "NRAL"),
    "paypal": Value("secret", lambda r: _mixed(r, 60)),
    "hubspot": Value("secret", lambda r: "pat-na1-" + "-".join(_s(r, n, HEX) for n in (8, 4, 4, 4, 12))),
    "fb1": Value("secret", lambda r: "Fb_" + _mixed(r, 8) + "!"),
    "fb2": Value("secret", lambda r: "Sv_" + _mixed(r, 8) + "!"),
    "concat_a": Value("secret", lambda r: "Inl_" + _s(r, 4)),
    "concat_b": Value("secret", lambda r: "Pw_" + _s(r, 4, string.digits)),
    "pg_pw": Value("secret", lambda r: "Pg_" + _mixed(r, 8) + "!"),
    "discord": Value("secret", lambda r: _s(r, 68, ALNUM + "_-")),
    "sendgrid": Value("secret", lambda r: "SG." + "x" * 56),
    "square": Value("secret", lambda r: "sq0atp-" + "x" * 32),
    "mongo_root_pw": Value("secret", lambda r: _mixed(r, 16)),
    "rabbit_pw": Value("secret", lambda r: _mixed(r, 16)),
    "shared": Value("secret", lambda r: _mixed(r, 32)),
    "hash": Value("secret", lambda r: _s(r, 53, ALNUM + "./")),
    # usernames
    "mongo_user": Value("username", lambda r: "mongo_" + _s(r, 5, string.ascii_lowercase)),
    "rabbit_user": Value("username", lambda r: "rabbit_" + _s(r, 5, string.ascii_lowercase)),
    "primary_user": Value("username", lambda r: "primary_" + _s(r, 5, string.ascii_lowercase)),
    "const_user": Value("username", lambda r: "production_" + _s(r, 5, string.ascii_lowercase)),
    "mysql_user": Value("username", lambda r: "appsvc" + _s(r, 3, string.digits)),
    # identifiers
    "twilio_sid": Value("identifier", lambda r: "AC" + _s(r, 32, HEX)),
    "tenant": Value("identifier", lambda r: "-".join(_s(r, n, HEX) for n in (8, 4, 4, 4, 12))),
    "client": Value("identifier", lambda r: _mixed(r, 20)),
    "pk": Value("identifier", lambda r: "pk_live_" + _s(r, 24)),
    "phone": Value("identifier", lambda r: "+1415" + _s(r, 7, string.digits)),
    # hosts
    "db_host": Value("host", lambda r: f"db-prod-{_s(r, 4, string.ascii_lowercase)}.internal.{ORG}"),
    "rds_label": Value("host", lambda r: "pg-" + _s(r, 6, string.ascii_lowercase)),
    "private_ip": Value("host", lambda r: f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"),
    "corp_host": Value("host", lambda r: f"SQLPROD{_s(r, 2, string.digits)}.corp.internal"),
    "bastion": Value("host", lambda r: f"bastion-{_s(r, 3, string.ascii_lowercase)}.{ORG}"),
    "mongo_host": Value("host", lambda r: f"mongo-{_s(r, 4, string.ascii_lowercase)}.{ORG}"),
    "bucket": Value("host", lambda r: "corp-bench-" + _s(r, 6, string.ascii_lowercase)),
    # must stay unchanged
    "smtp": Value("keep", lambda r: "smtp.sendgrid.net"),
    "app_name": Value("keep", lambda r: "app.name"),
    "user_id_col": Value("keep", lambda r: "user_profile_settings"),
    "prefixed_user_text": Value("keep", lambda r: "prod_reporting"),
}


FILES: dict[str, str] = {
    "app/Config/Connections.php": (
        "<?php\nclass Connections {{\n"
        "    public const MONGODB_URI = 'mongodb://admin:{mongo_pw}@{mongo_host}:27017/app?authSource=admin';\n"
        "    public const REDIS_URL   = 'redis://:{redis_pw}@redis.{ORG}:6379/0';\n"
        "    public const PAGERDUTY_ROUTING_KEY = '{routing}';\n"
        "    public const NEW_RELIC_LICENSE = '{license}';\n"
        "}}\n"),
    "app/Config/Services.php": (
        "<?php\nreturn [\n"
        "    'oauth_secret' => '{oauth}',\n"
        "    'stripe'   => ['public_key' => '{pk}', 'secret' => '{stripe}'],\n"
        "    'twilio'   => ['account_sid' => '{twilio_sid}', 'phone_number' => '{phone}', 'auth_token' => '{shared}'],\n"
        "    'datadog'  => ['api_key' => '{shared}'],\n"
        "    'azure'    => ['tenant_id' => '{tenant}', 'client_id' => '{client}'],\n"
        "    'discord'  => ['webhook_url' => 'https://discord.com/api/webhooks/123456789012345678/{discord}'],\n"
        "    'mail'     => ['host' => '{smtp}'],\n"
        "];\n"),
    "app/Config/Database.php": (
        "<?php\nreturn [\n"
        "    'default' => ['hostname' => '{db_host}', 'port' => 3306],\n"
        "    'rds'     => ['hostname' => '{rds_label}.rds.amazonaws.com'],\n"
        "    'legacy'  => ['hostname' => '{private_ip}'],\n"
        "    'mssql'   => ['hostname' => '{corp_host}'],\n"
        "];\n"),
    "app/Controllers/DatabaseController.php": (
        "<?php\n$connections = [\n"
        "    'primary' => ['host' => 'db', 'user' => '{primary_user}', 'pass' => '{db_pw}'],\n"
        "];\n"
        "$pass = getenv('DB_PASS') ?: '{fb1}';\n"
        "$pass2 = $_SERVER['DB_PASS'] ?? '{fb2}';\n"
        "$mysqli = mysqli_connect('db', '{mysql_user}', '{db_pw}');\n"
        "$name = config('{app_name}');\n"),
    "app/Controllers/LegacyConnectionController.php": (
        "<?php\n$p = '{concat_a}' . '{concat_b}' . '77!';\n"
        "$conn = mysqli_connect('db', 'inline_user', $p, 'shop');\n"
        '$connString = "host=pg-ssl.{ORG} port=5432 dbname=ssl_database user=ssl_user password={pg_pw} sslmode=require";\n'
        "$pg = pg_connect($connString);\n"),
    "app/Helpers/credentials_helper.php": (
        "<?php\nfunction get_api_key(string $service): ?string\n{{\n"
        "    $keys = [\n        'paypal'  => '{paypal}',\n        'hubspot' => '{hubspot}',\n    ];\n"
        "    return $keys[$service] ?? null;\n}}\n"
        "// Connects to {bastion} first\n"),
    "app/Libraries/ExternalApiClient.php": (
        "<?php\n$merchantKey = '{merchant}';\n"
        "$sendgrid_api_key = '{sendgrid}';\n"
        "define('SQUARE_ACCESS_TOKEN', '{square}');\n"
        "$label = '{prefixed_user_text}';\n"
        "$cols = ['{user_id_col}'];\n"),
    "app/Config/Constants.php": (
        "<?php\ndefined('DB_USER') || define('DB_USER', '{const_user}');\n"
        "defined('DB_PASS') || define('DB_PASS', '{db_pw}');\n"
        "define('HASH_SALT', 'my_unique_salt_{salt}');\n"),
    "docker-compose.yml": (
        "services:\n  app:\n    environment:\n"
        "      - SESSION_BLOB=base64:{oauth}{app_tail}=\n"
        "      - AWS_ACCESS_KEY_ID={aws_id}\n"
        "      - AWS_SECRET_ACCESS_KEY={aws_secret}\n"
        "      - STRIPE_KEY={stripe}\n"
        "      - MONGO_INITDB_ROOT_USERNAME={mongo_user}\n"
        "      - MONGO_INITDB_ROOT_PASSWORD={mongo_root_pw}\n"
        "      - RABBITMQ_DEFAULT_USER={rabbit_user}\n"
        "      - RABBITMQ_DEFAULT_PASS={rabbit_pw}\n"
        "      - DB_HOST=db\n"),
    "config/services.yaml": "facebook:\n  app_secret: {shared}\nstorage:\n  bucket: {bucket}\n",
    "database/seed.php": "<?php\n$admin = ['name' => 'ops', 'hash' => '$2y$10${hash}'];\n",
    "database/notes.sql": "-- Insert default admin user (password: {comment_pw})\nSELECT 1;\n",
}


def render(seed: int = 4242) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """(files, values) where values maps name -> (category, value)."""
    r = random.Random(seed)
    values = {name: (v.category, v.make(r)) for name, v in VALUES.items()}
    fmt = {name: value for name, (_, value) in values.items()} | {"ORG": ORG}
    return {path: tmpl.format(**fmt) for path, tmpl in FILES.items()}, values
