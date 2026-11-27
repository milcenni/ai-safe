"""PHP database connection credentials: native sinks (PDO, mysqli, ...),
connect-like wrappers (``$this->db->connect(...)``), and Laravel /
CodeIgniter configuration forms. All values are synthetic and generated at
runtime; short low-entropy passwords are used on purpose, because the call
context alone identifies them."""

import random

import pytest

from ai_safe.detectors import BuiltinDetector
from conftest import all_text, prepare, short_word

_R = random.Random(20261127)


def word(n: int = 5) -> str:
    """Short lowercase value such as a weak real-world password."""
    return short_word(_R, n)


def found(text: str, path: str = "db.php") -> list[str]:
    return [m.secret for m in BuiltinDetector().scan_text(text, path)]


# (user, password) -> PHP source. Both the user and the password must be found.
SINKS = {
    "pdo": lambda u, p: f"<?php\n$db = new PDO('mysql:host=db;dbname=app', '{u}', '{p}');\n",
    "pdo-ns-options": lambda u, p: f'<?php\n$db = new \\PDO("mysql:host=db", "{u}", "{p}", [PDO::ATTR_ERRMODE => 1]);\n',
    "pdo-multiline": lambda u, p: f"<?php\n$db = new PDO(\n    $dsn,\n    '{u}',\n    '{p}'\n);\n",
    "mysqli-connect": lambda u, p: f"<?php\n$c = mysqli_connect('db', '{u}', '{p}', 'app');\n",
    "mysqli-new": lambda u, p: f"<?php\n$c = new mysqli('db', '{u}', '{p}', 'app', 3306);\n",
    "mysqli-real-connect": lambda u, p: f"<?php\nmysqli_real_connect($link, 'db', '{u}', '{p}', 'app');\n",
    "mysqli-real-connect-method": lambda u, p: f"<?php\n$m->real_connect('db', '{u}', '{p}');\n",
    "mysql-connect": lambda u, p: f"<?php\n$c = mysql_connect('db', '{u}', '{p}');\n",
    "mysql-pconnect": lambda u, p: f"<?php\n$c = mysql_pconnect('db', '{u}', '{p}');\n",
    "oci-connect": lambda u, p: f"<?php\n$c = oci_connect('{u}', '{p}', 'db/XE');\n",
    "odbc-connect": lambda u, p: f"<?php\n$c = odbc_connect('DSN=app', '{u}', '{p}');\n",
    "ci-this-db-connect": lambda u, p: f"<?php\n$this->db->connect('db', '{u}', '{p}');\n",
    "custom-connect-2-args": lambda u, p: f"<?php\ncustom_connect('{u}', '{p}');\n",
    "custom-connect-4-args": lambda u, p: f"<?php\ncustom_connectv2('db', '{u}', '{p}', 'app');\n",
    "static-connect": lambda u, p: f"<?php\nDatabase::connect('db', '{u}', '{p}');\n",
}


@pytest.mark.parametrize("name", sorted(SINKS))
def test_connect_call_credentials_detected(name):
    u, p = word(), word(4)
    secrets = found(SINKS[name](u, p))
    assert p in secrets, (name, secrets)
    assert u in secrets, (name, secrets)


def test_pg_connect_conninfo_password_detected():
    p = word(4)
    assert p in found(f'<?php\n$c = pg_connect("host=db dbname=app user=app password={p}");\n')
    assert p in found(f"<?php\n$c = pg_pconnect(\"host=db password='{p}' user=app\");\n")


# password -> PHP / config text. Laravel and CodeIgniter configuration forms.
FRAMEWORK = {
    "laravel-env-default.php": lambda p: f"<?php\nreturn ['password' => env('DB_PASSWORD', '{p}')];\n",
    "laravel-config-array.php": lambda p: f"<?php\nconfig(['database.connections.mysql.password' => '{p}']);\n",
    "laravel-config-set.php": lambda p: f"<?php\nConfig::set('database.connections.mysql.password', '{p}');\n",
    "laravel-capsule.php": lambda p: f"<?php\n$capsule->addConnection(['driver' => 'mysql', 'password' => '{p}']);\n",
    "ci3-database.php": lambda p: f"<?php\n$db['default']['password'] = '{p}';\n",
    "ci3-config-index.php": lambda p: f'<?php\n$config["password"] = "{p}";\n',
    "ci3-array.php": lambda p: f"<?php\n$db['default'] = array('hostname' => 'db', 'password' => '{p}');\n",
    "ci4-config.php": lambda p: f"<?php\nclass Database {{\n    public array $default = ['password' => '{p}'];\n}}\n",
    "ci4.env": lambda p: f"database.default.password = {p}\n",
    "wp-define.php": lambda p: f"<?php\ndefine('DB_PASSWORD', '{p}');\n",
    "property.php": lambda p: f"<?php\n$this->db->password = '{p}';\n",
}


@pytest.mark.parametrize("name", sorted(FRAMEWORK))
def test_framework_config_password_detected(name):
    p = word(4) + "9"
    assert p in found(FRAMEWORK[name](p), name), name


NOT_SECRETS = [
    "<?php\n$db = new PDO($dsn, $user, $pass);\n",
    "<?php\n$db = new PDO($dsn, $cfg['user'], $cfg['password']);\n",
    "<?php\n$c = mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);\n",
    "<?php\n$c = mysqli_connect('localhost', 'root', '', 'app');\n",
    "<?php\n$c = mysqli_connect('db', \"$user\", \"{$pass}\");\n",
    "<?php\n$db = DB::connection('mysql');\n",
    "<?php\n$db = \\Config\\Database::connect('default');\n",
    "<?php\n$this->db->connect();\n",
    "<?php\n$redis->connect('redis-cache', 6379);\n",
    "<?php\n$redis->connect('127.0.0.1', 6379, 2.5);\n",
    "<?php\nsocket_connect($sock, '10.0.0.1', 8080);\n",
    "<?php\n$conn = ssh2_connect('bastion', 22);\n",
    "<?php\n$this->disconnect('db', 'reason', 'now');\n",
    "<?php\ncustom_connect('db.example.com', 'app');\n",
    "<?php\nreturn ['password' => env('DB_PASSWORD', '')];\n",
    "<?php\n$db = new PDO($dsn, 'root', getenv('DB_PASSWORD'));\n",
]


@pytest.mark.parametrize("text", NOT_SECRETS)
def test_connect_false_positive_guard(text):
    assert found(text) == []


def test_default_usernames_and_hosts_not_redacted():
    """Usernames such as ``postgres`` are replaced everywhere once redacted;
    common defaults and hostnames must stay untouched."""
    p = word(4)
    secrets = found(f"<?php\n$c = pg_like_connect('localhost', 'postgres', '{p}');\n")
    assert secrets == [p]


def test_connect_credentials_never_reach_workspace(make_repo):
    files, values = {}, []
    for i, (name, fn) in enumerate(sorted(SINKS.items())):
        u, p = word(6), word(6) + "7"
        values += [u, p]
        files[f"src/{i}-{name}.php"] = fn(u, p)
    p = prepare(make_repo(files))
    text = all_text(p.ws)
    assert [v for v in values if v in text] == []
    assert p.verification.passed


# --- non-database services --------------------------------------------------

# (user, password) -> PHP source. Both must be found.
SERVICE_PAIRS = {
    "ftp-login": lambda u, p: f"<?php\nftp_login($ftp, '{u}', '{p}');\n",
    "ldap-bind": lambda u, p: f"<?php\nldap_bind($ds, 'cn={u},dc=example,dc=com', '{p}');\n",
    "ldap-sasl-bind": lambda u, p: f"<?php\nldap_sasl_bind($ds, '{u}', '{p}', 'DIGEST-MD5');\n",
    "imap-open": lambda u, p: f"<?php\n$mb = imap_open('{{imap.example.com:993/imap/ssl}}INBOX', '{u}', '{p}');\n",
    "pop3-imap-open": lambda u, p: f"<?php\n$mb = imap_open('{{mail.example.com:995/pop3/ssl}}', '{u}', '{p}');\n",
    "pop3-lib-login": lambda u, p: f"<?php\n$pop3->login('{u}', '{p}');\n",
    "ssh2-auth-password": lambda u, p: f"<?php\nssh2_auth_password($session, '{u}', '{p}');\n",
    "phpseclib-login": lambda u, p: f"<?php\n$sftp->login('{u}', '{p}');\n",
    "redis-acl-auth": lambda u, p: f"<?php\n$redis->auth('{u}', '{p}');\n",
    "redis-acl-auth-array": lambda u, p: f"<?php\n$redis->auth(['{u}', '{p}']);\n",
    "amqp": lambda u, p: f"<?php\n$c = new AMQPStreamConnection('mq', 5672, '{u}', '{p}');\n",
    "amqp-ssl": lambda u, p: f"<?php\n$c = new \\PhpAmqpLib\\Connection\\AMQPSSLConnection('mq', 5671, '{u}', '{p}', '/');\n",
    "memcached-sasl": lambda u, p: f"<?php\n$m->setSaslAuthData('{u}', '{p}');\n",
    "minio-aws-credentials": lambda u, p: f"<?php\n$creds = new Aws\\Credentials\\Credentials('{u}', '{p}');\n",
    "mysqli-change-user": lambda u, p: f"<?php\n$m->change_user('{u}', '{p}', 'app');\n",
    "curl-userpwd": lambda u, p: f"<?php\ncurl_setopt($ch, CURLOPT_USERPWD, '{u}:{p}');\n",
    "curl-userpwd-array": lambda u, p: f"<?php\ncurl_setopt_array($ch, [CURLOPT_USERPWD => \"{u}:{p}\"]);\n",
}


@pytest.mark.parametrize("name", sorted(SERVICE_PAIRS))
def test_service_call_credentials_detected(name):
    u, p = word(6), word(4)
    secrets = found(SERVICE_PAIRS[name](u, p))
    # A larger match may cover the password ('user:pw' as one CURLOPT_USERPWD value).
    assert any(p in s for s in secrets), (name, secrets)
    assert any(u in s for s in secrets), (name, secrets)


# password -> source. Password-only calls and configuration forms.
SERVICE_PASSWORDS = {
    "redis-auth.php": lambda p: f"<?php\n$redis->auth('{p}');\n",
    "predis-auth.php": lambda p: f"<?php\n$client->auth('{p}');\n",
    "guzzle-auth.php": lambda p: f"<?php\n$http->get($url, ['auth' => ['svc', '{p}']]);\n",
    "kafka-sasl.php": lambda p: f"<?php\n$conf->set('sasl.password', '{p}');\n",
    "kafka.properties": lambda p: f'sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="svc" password="{p}";\n',
    "minio.env": lambda p: f"MINIO_ROOT_PASSWORD={p}\n",
    "minio-s3-config.php": lambda p: f"<?php\nnew S3Client(['endpoint' => 'http://minio:9000', 'credentials' => ['key' => 'ak', 'secret' => '{p}']]);\n",
}


@pytest.mark.parametrize("name", sorted(SERVICE_PASSWORDS))
def test_service_password_detected(name):
    p = word(5) + "9"
    assert p in found(SERVICE_PASSWORDS[name](p), name), name


SERVICE_NOT_SECRETS = [
    "<?php\n$user = auth('api')->user();\n",
    "<?php\n$this->middleware('auth');\n",
    "<?php\nAuth::login($user, true);\n",
    "<?php\n$redis->auth($password);\n",
    "<?php\n$redis->auth(config('database.redis.default.password'));\n",
    "<?php\nftp_login($ftp, $user, $pass);\n",
    "<?php\nldap_bind($ds);\n",
    "<?php\n$browser->login('user@example.com', 'password');\n",
    "<?php\ncurl_setopt($ch, CURLOPT_USERPWD, \"$user:$pass\");\n",
    "<?php\ncurl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $pass);\n",
]


@pytest.mark.parametrize("text", SERVICE_NOT_SECRETS)
def test_service_false_positive_guard(text):
    assert found(text) == []


def test_service_credentials_never_reach_workspace(make_repo):
    files, values = {}, []
    for i, (name, fn) in enumerate(sorted(SERVICE_PAIRS.items())):
        u, p = word(7), word(6) + "7"
        values += [u, p]
        files[f"src/{i}-{name}.php"] = fn(u, p)
    p = prepare(make_repo(files))
    text = all_text(p.ws)
    assert [v for v in values if v in text] == []
    assert p.verification.passed
