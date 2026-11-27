"""Infrastructure sanitization: internal host names, domains, IP addresses,
buckets and cloud IDs become restorable placeholders. Host names are
synthetic (``corp-x.net`` style); no real organisation is named."""

from __future__ import annotations

import json
import random
import re
import string

import pytest

from conftest import all_text, builtin_config, prepare, write

from ai_safe.config import ConfigError, InfrastructureConfig, parse_config
from ai_safe.credential_map import INFRA_MAP_FILE, load_infra_map
from ai_safe.infra import classify_ip, detect_infra, provider_split, pseudonym
from ai_safe.integration import integrate
from ai_safe.review import review_session

R = random.Random(7007)
HOST_PH = r"\$\{AI_SAFE_HOST_[A-Z0-9_]+\}"
APPROVE = lambda rr, patch: True  # noqa: E731


def rand(n: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(R.choice(alphabet) for _ in range(n))


ORG = f"corp{rand(4)}.net"  # the organisation's (synthetic) domain


def hits(texts: dict[str, str], **cfg) -> list[tuple[str, str]]:
    return [(h.kind, h.value) for h in detect_infra(texts, InfrastructureConfig(**cfg))]


# ---------------------------------------------------------------------------
# Detection, table-driven (section 7.6 before -> after, plus "unchanged" rows)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line,kind,value", [
    (f"$a = ['hostname' => 'db-prod-mysql-01.internal.{ORG}'];", "host", f"db-prod-mysql-01.internal.{ORG}"),
    ("$a = ['hostname' => 'SQLPROD01.corp.internal'];", "host", "SQLPROD01.corp.internal"),
    ("$a = ['hostname' => '10.0.15.42'];", "ip", "10.0.15.42"),
    ("$host = '192.168.50.100';", "ip", "192.168.50.100"),
    (f"$a = ['cluster_url' => 'https://k8s-api.{ORG}:6443'];", "host", f"k8s-api.{ORG}"),
    ("$a = ['hostname' => 'postgres-master.rds.amazonaws.com'];", "host", "postgres-master"),
    ("$supabaseUrl = 'https://abcdefgh.supabase.co';", "host", "abcdefgh"),
    (f"$dsn = 'Driver={{MySQL ODBC 8.0 Driver}};Server=odbc-mysql.{ORG};Database=odbc_database;';", "host", f"odbc-mysql.{ORG}"),
    (f'$c = "host=pg-ssl.{ORG} port=5432 dbname=ssl_database";', "host", f"pg-ssl.{ORG}"),
    ("$host = 'legacy-mysql.company.old';", "host", "legacy-mysql.company.old"),
    ("$arn = 'arn:aws:kms:us-east-1:123456789012:key/abc';", "account", "123456789012"),
])
def test_detected(line, kind, value):
    assert (kind, value) in hits({"a.php": "<?php\n" + line + "\n"})


@pytest.mark.parametrize("text,path", [
    ("$a = ['host' => 'smtp.sendgrid.net'];", "a.php"),
    ("$a = ['host' => 'smtp.mailgun.org', 'h2' => 'smtp.gmail.com', 'h3' => 'smtp.office365.com'];", "a.php"),
    ("$a = ['host' => 'email-smtp.us-east-1.amazonaws.com'];", "a.php"),
    ("$a = ['host' => 'localhost', 'ip' => '127.0.0.1'];", "a.php"),
    ("services:\n  app:\n    environment:\n      - DB_HOST=db\n      - REDIS_HOST=redis\n", "docker-compose.yml"),
    ("require 'bootstrap.php'; require_once 'Paths.php';", "a.php"),
    ("$v = config('app.name'); $l = 'log.info'; $x = 'user.id';", "a.php"),
    ("$a = ['version' => '10.0.1.2']; $d = 'MySQL ODBC 8.0 Driver';", "a.php"),
    ("namespace App\\Http\\Controllers;", "a.php"),
    ("$this->db.config.host = $x;", "a.js"),
    ("$a = ['host' => 'db.example.com', 'h' => 'api.test', 'u' => 'https://github.com/x/y'];", "a.php"),
    ("ip: 8.8.8.8\n", "c.yaml"),
])
def test_unchanged(text, path):
    assert hits({path: "<?php\n" + text + "\n" if path.endswith(".php") else text}) == []


def test_lists_brokers_and_weak_mentions():
    texts = {
        "q.php": f"<?php\n$c = ['brokers' => 'kafka-1.{ORG}:9092,kafka-2.{ORG}:9092'];\n",
        "notes.php": f"<?php\n// Connects to bastion.{ORG} first\n",
    }
    found = hits(texts)
    assert ("host", f"kafka-1.{ORG}") in found and ("host", f"kafka-2.{ORG}") in found
    assert ("host", f"bastion.{ORG}") in found  # weak, but the org domain is known from strong evidence


def test_weak_mention_without_org_evidence_is_kept():
    assert hits({"notes.php": "<?php\n// see docs.vendor-x.com for details\n"}) == []


def test_ip_modes_and_wildcards():
    assert classify_ip("10.1.2.3", "private") == "ip" and classify_ip("100.64.1.1", "private") == "ip"
    assert classify_ip("8.8.8.8", "private") is None and classify_ip("8.8.8.8", "all") == "ip"
    assert classify_ip("127.0.0.1", "all") is None and classify_ip("255.255.255.255", "all") is None
    assert classify_ip("fd12:3456::1", "private") == "ip"
    assert ("net", "10.0.0") in hits({"g.sql": "CREATE USER 'b'@'10.0.0.%' IDENTIFIED BY 'x';\n"})
    assert hits({"a.php": "<?php\n$h = ['host' => '10.0.15.42'];\n"}, ip_addresses="none") == []


def test_provider_split():
    assert provider_split("postgres-master.rds.amazonaws.com") == (len("postgres-master"), False)
    assert provider_split("mydb.abc123.us-east-1.rds.amazonaws.com") == (len("mydb.abc123"), False)
    assert provider_split("email-smtp.eu-west-1.amazonaws.com") == (0, True)
    assert provider_split("acme.blob.core.windows.net") == (4, False)
    assert provider_split("db.corp-x.net") is None


def test_buckets_and_projects():
    found = hits({"s.yaml": "storage:\n  bucket: corp-prod-uploads\n  project_id: corp-prod-123456\n",
                  "a.py": "URL = 's3://corp-logs-bucket/2024/'\n"})
    assert ("bucket", "corp-prod-uploads") in found and ("project", "corp-prod-123456") in found
    assert ("bucket", "corp-logs-bucket") in found


def test_concatenated_host():
    found = hits({"l.php": f"<?php\n$h = 'inline' . '-mysql' . '.{ORG}';\n$x = ['host' => 'db.{ORG}'];\n"})
    assert any(k == "host" and "-mysql" in v for k, v in found)


def test_org_and_keep_domains():
    assert ("host", "build01.lab") not in hits({"n.md": "build01.lab is down\n"})
    assert ("host", "build01.lab") in hits({"n.md": "build01.lab is down\n"}, org_domains=["lab"])
    assert hits({"a.php": f"<?php\n$x = ['host' => 'db.{ORG}'];\n"}, keep_domains=[ORG]) == []


def test_config_validation():
    with pytest.raises(ConfigError):
        parse_config({"sanitization": {"infrastructure": {"org_domains": ["not a domain"]}}})
    with pytest.raises(ConfigError):
        parse_config({"sanitization": {"infrastructure": {"ip_addresses": "some"}}})


# ---------------------------------------------------------------------------
# Sanitization end to end
# ---------------------------------------------------------------------------

def _repo(make_repo):
    pw = "Mg0_" + rand(10, string.ascii_letters + string.digits) + "@x!"
    return make_repo({
        "app/Config/Database.php": (
            "<?php\nreturn [\n"
            f"  'default' => ['hostname' => 'db-prod-mysql-01.internal.{ORG}', 'port' => 3306],\n"
            "  'rds' => ['hostname' => 'postgres-master.rds.amazonaws.com'],\n"
            "  'ip' => ['hostname' => '10.0.15.42'],\n"
            "  'mail' => ['host' => 'smtp.sendgrid.net'],\n];\n"),
        "app/Lib/Sftp.php": f"<?php\nclass Sftp {{\n    private string $sftpHost = 'sftp.secure-files.{ORG}';\n}}\n",
        "config/database.json": json.dumps({
            "host": f"DB-PROD-MYSQL-01.internal.{ORG}",
            "uri": f"mongodb://mongo_admin:{pw}@mongo-primary.{ORG}:27017/app_data?authSource=admin",
        }) + "\n",
        "docs/ops.md": f"Connect through bastion.{ORG} first.\n",
    }), pw


def test_end_to_end_sanitization(make_repo):
    repo, pw = _repo(make_repo)
    p = prepare(repo)
    assert p.verification.passed, [i.public() for i in p.verification.issues if i.severity.blocking]
    text = all_text(p.ws)
    for host in (f"db-prod-mysql-01.internal.{ORG}", "postgres-master", "10.0.15.42", f"mongo-primary.{ORG}",
                 f"bastion.{ORG}", f"sftp.secure-files.{ORG}", ORG):
        assert host.lower() not in text.lower(), host
    assert pw not in text
    db = (p.ws / "app/Config/Database.php").read_text()
    assert re.search(HOST_PH + r"\.rds\.amazonaws\.com", db)
    assert re.search(r"\$\{AI_SAFE_IP_[A-Z0-9_]+\}", db)
    assert "'smtp.sendgrid.net'" in db
    # same host (case-insensitive) -> same placeholder in every file
    js = json.loads((p.ws / "config/database.json").read_text())
    ph_php = re.search(r"'default' => \['hostname' => '(\$\{[^}]+\})'", db).group(1)
    assert js["host"] == ph_php
    assert re.fullmatch(r"mongodb://mongo_admin:\$\{AI_SAFE_SECRET_[A-Z0-9_]+\}@" + HOST_PH + r":27017/app_data\?authSource=admin",
                        js["uri"]), js["uri"]
    # placeholder names never contain a host label
    names = re.findall(r"AI_SAFE_(?:HOST|IP|NET|DOMAIN)_[A-Z0-9_]+", text)
    assert names and not any(lab in n.lower() for n in names for lab in ("prod", "mysql", "sftp", "secure", "mongo", "bastion"))
    # mapping + docs
    infra = load_infra_map(p.session.state_path)
    assert {e.kind for e in infra} >= {"host", "ip"}
    assert (p.session.state_path / INFRA_MAP_FILE).stat().st_mode & 0o077 == 0
    doc = (p.ws / "AI_SAFE_PLACEHOLDERS.md").read_text()
    assert "## Infrastructure placeholders" in doc and ORG not in doc
    assert ORG not in (p.session.state_path / "credential-map.json").read_text()


def test_infrastructure_can_be_disabled(make_repo):
    repo, _ = _repo(make_repo)
    cfg = builtin_config()
    cfg.sanitization.infrastructure.enabled = False
    p = prepare(repo, cfg)
    assert f"db-prod-mysql-01.internal.{ORG}" in all_text(p.ws)


def test_scope_domain(make_repo):
    repo, _ = _repo(make_repo)
    cfg = builtin_config()
    cfg.sanitization.infrastructure.scope = "domain"
    p = prepare(repo, cfg)
    assert p.verification.passed, [i.public() for i in p.verification.issues if i.severity.blocking]
    db = (p.ws / "app/Config/Database.php").read_text()
    assert re.search(r"'db-prod-mysql-01\.internal\.\$\{AI_SAFE_DOMAIN_[A-Z0-9_]+\}'", db), db
    assert ORG not in all_text(p.ws)


def test_pseudonym_mode(make_repo):
    repo, _ = _repo(make_repo)
    cfg = builtin_config()
    cfg.sanitization.infrastructure.mode = "pseudonym"
    p = prepare(repo, cfg)
    assert p.verification.passed, [i.public() for i in p.verification.issues if i.severity.blocking]
    db = (p.ws / "app/Config/Database.php").read_text()
    assert re.search(r"'hostname' => 'h-[0-9a-f]{6}\.d-[0-9a-f]{6}\.invalid'", db), db
    assert re.search(r"'hostname' => '198\.1[89]\.\d+\.\d+'", db), db
    assert ORG not in all_text(p.ws)
    assert pseudonym("ip", "ab" * 12, "fd00::1").startswith("2001:db8:")


# ---------------------------------------------------------------------------
# Review and integration: hosts round-trip, secrets never do
# ---------------------------------------------------------------------------

def test_hosts_are_restored_on_integration(make_repo):
    repo, pw = _repo(make_repo)
    p = prepare(repo)
    db = p.ws / "app/Config/Database.php"
    db.write_text(db.read_text().replace("'port' => 3306", "'port' => 3307"))
    sftp = p.ws / "app/Lib/Sftp.php"
    ph = re.search(HOST_PH, sftp.read_text()).group(0)
    sftp.write_text(sftp.read_text().replace("}\n", f"    public function host(): string {{ return '{ph}'; }}\n}}\n"))
    rr = review_session(p.session, p.cfg, p.scanner)
    assert rr.passed, [i.public() for i in rr.issues if i.severity.blocking]
    assert any(i.code == "host-placeholder-in-new-code" for i in rr.issues)
    res = integrate(p.session, p.cfg, p.scanner, confirm=APPROVE, cwd=repo)
    assert not res.aborted, res.reason
    out = (repo / "app/Config/Database.php").read_text()
    assert f"'hostname' => 'db-prod-mysql-01.internal.{ORG}', 'port' => 3307" in out
    assert "AI_SAFE_" not in out
    assert f"return 'sftp.secure-files.{ORG}';" in (repo / "app/Lib/Sftp.php").read_text()


def test_secret_placeholders_are_never_restored(make_repo):
    repo, pw = _repo(make_repo)
    p = prepare(repo)
    js = p.ws / "config/database.json"
    js.write_text(js.read_text().replace("app_data", "app_data2"))  # touches the line with the secret placeholder
    rr = review_session(p.session, p.cfg, p.scanner)
    assert {i.code for i in rr.issues if i.severity.blocking} & {"conflict", "placeholder-in-new-code"}
    assert not rr.passed and pw in (repo / "config/database.json").read_text()


def test_invented_host_placeholder_is_rejected(make_repo):
    repo, _ = _repo(make_repo)
    p = prepare(repo)
    write(p.ws, {"app/New.php": "<?php\n$h = '${AI_SAFE_HOST_FAKE}';\n"})
    rr = review_session(p.session, p.cfg, p.scanner)
    assert "unknown-placeholder" in {i.code for i in rr.issues if i.severity.blocking}


def test_ai_introduced_internal_host_is_flagged(make_repo):
    repo, _ = _repo(make_repo)
    p = prepare(repo)
    write(p.ws, {"app/New.php": "<?php\n$h = ['host' => 'cache01.corp.internal'];\n"})
    rr = review_session(p.session, p.cfg, p.scanner)
    assert any(i.code == "host-introduced" for i in rr.issues)


def test_invented_pseudonym_is_rejected(make_repo):
    repo, _ = _repo(make_repo)
    cfg = builtin_config()
    cfg.sanitization.infrastructure.mode = "pseudonym"
    p = prepare(repo, cfg)
    write(p.ws, {"app/New.php": "<?php\n$h = 'h-abcdef.d-123456.invalid';\n"})
    rr = review_session(p.session, p.cfg, p.scanner)
    assert "unknown-pseudonym" in {i.code for i in rr.issues if i.severity.blocking}


def test_no_restore_when_disabled(make_repo):
    repo, _ = _repo(make_repo)
    cfg = builtin_config()
    cfg.sanitization.infrastructure.restore_on_integrate = False
    p = prepare(repo, cfg)
    sftp = p.ws / "app/Lib/Sftp.php"
    ph = re.search(HOST_PH, sftp.read_text()).group(0)
    sftp.write_text(sftp.read_text().replace("}\n", f"    public function host(): string {{ return '{ph}'; }}\n}}\n"))
    rr = review_session(p.session, p.cfg, p.scanner)
    assert "placeholder-in-new-code" in {i.code for i in rr.issues if i.severity.blocking}
