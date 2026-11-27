"""Infrastructure detection: host names, domains, IP addresses, buckets and
cloud account / project IDs.

The AI must not learn the organisation's internal topology. Hosts are not
credentials, so they are replaced by *restorable* placeholders
(``${AI_SAFE_HOST_...}``, ``${AI_SAFE_IP_...}``, ...) and written back on
integration. Detection runs over the whole working tree in two passes:

1. **Strong evidence** - a value under a host-like key (``host``, ``server``,
   ``brokers``, ...), a URL authority, a DSN component (``host=``,
   ``Server=``), a ``-h`` flag, an SQL ``'user'@'host'`` grant, an internal
   pseudo-TLD (``.internal``, ``.corp``, ...) or a configured ``org_domains``
   suffix. The registrable domains found this way, plus email domains, form
   the organisation's domain set.
2. **Weak evidence** - any other FQDN in a string literal, comment or
   document is replaced only when its registrable domain is in that set. This
   keeps dotted config keys (``'app.name'``, ``'log.info'``) untouched.

Code identifiers outside string literals and comments are never looked at.
Public service hosts (``smtp.sendgrid.net``, ``github.com``, ...), loopback
addresses, reserved names and file names are kept. Provider hosts keep their
provider suffix (``${AI_SAFE_HOST_...}.rds.amazonaws.com``).
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from ai_safe.classifier import file_kind, is_sensitive_key, key_words
from ai_safe.config import InfrastructureConfig
from ai_safe.php_calls import fold_literal

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

INTERNAL_TLDS = {"internal", "local", "localdomain", "corp", "lan", "intranet", "private", "svc", "home", "arpa"}
_GTLDS = set("""
com net org edu gov mil int info biz name pro aero coop museum mobi asia tel travel jobs cat post
io ai app dev cloud tech online site xyz shop store blog news live life world space website digital agency
company solutions services systems network email media studio design global group center today rocks codes
software tools host hosting server domains page link click top club vip win work works team zone one plus
inc llc ltd gmbh bank insurance finance capital money pay security consulting ventures partners holdings
international academy university school education health care clinic legal law realty properties estate
land city nyc london berlin paris tokyo amsterdam wien swiss africa eus scot wales bayern koeln hamburg
gle goog google amazon aws azure microsoft apple run build cool fun ink art photo pics video tv fm am
""".split())
# Extensions that are file names, not TLDs (even when they are also ccTLDs: .py, .md, .sh, .rs ...).
FILE_EXTENSIONS = {
    "php", "phtml", "inc", "py", "pyc", "rb", "rs", "go", "sh", "bash", "zsh", "ps1", "bat", "cmd", "md", "rst",
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "json", "yml", "yaml", "toml", "ini", "cfg", "conf",
    "lock", "txt", "log", "csv", "tsv", "xml", "html", "htm", "css", "scss", "sass", "less", "png", "jpg", "jpeg",
    "gif", "svg", "webp", "ico", "bmp", "zip", "gz", "tgz", "bz2", "xz", "rar", "7z", "tar", "sql", "pem", "key",
    "crt", "cer", "der", "p12", "pfx", "jar", "war", "class", "java", "kt", "kts", "scala", "c", "h", "cc", "cpp",
    "hpp", "cs", "swift", "m", "mm", "pl", "pm", "lua", "r", "dart", "ex", "exs", "erl", "hrl", "clj", "env",
    "dist", "example", "sample", "tmpl", "tpl", "twig", "blade", "mustache", "hbs", "ejs", "pug", "map", "min",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "mp3", "mp4", "wav", "ogg", "webm", "mov", "avi",
    "woff", "woff2", "ttf", "otf", "eot", "so", "dll", "exe", "bin", "o", "a", "lib", "dylib", "wasm", "proto",
    "graphql", "gql", "tf", "tfvars", "hcl", "service", "socket", "timer", "mount", "pid", "sock", "tmp", "bak",
    "old", "orig", "swp", "test", "spec", "d", "pub", "asc", "gpg", "sig", "patch", "diff", "po", "mo", "pot",
}
RESERVED_TLDS = {"example", "test", "invalid", "localhost"}
RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}
# Two-label public suffixes (registrable domain = three labels).
SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
                "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "co.za", "co.in", "com.sg", "com.tr", "co.kr",
                "com.ar", "com.tw", "com.hk", "co.il", "com.pl", "com.ua", "home.arpa", "cluster.local"}

# Provider hosts: customer labels are replaced, the provider suffix is kept.
PROVIDER_SUFFIXES = (
    ".blob.core.windows.net", ".file.core.windows.net", ".queue.core.windows.net", ".table.core.windows.net",
    ".database.windows.net", ".redis.cache.windows.net", ".servicebus.windows.net", ".vault.azure.net",
    ".documents.azure.com", ".azurewebsites.net", ".azurecr.io", ".cloudapp.azure.com", ".azure-api.net",
    ".supabase.co", ".psdb.cloud", ".mongodb.net", ".firebaseio.com", ".firebaseapp.com", ".web.app",
    ".herokuapp.com", ".cloudfront.net", ".ingest.sentry.io", ".atlassian.net", ".myshopify.com", ".okta.com",
    ".auth0.com", ".vercel.app", ".netlify.app", ".pages.dev", ".workers.dev", ".appspot.com", ".run.app",
    ".cloudfunctions.net", ".digitaloceanspaces.com", ".ondigitalocean.app", ".upstash.io", ".neon.tech",
    ".sharepoint.com", ".zendesk.com", ".my.salesforce.com",
)
_AWS_SERVICE_LABELS = {
    "rds", "cache", "s3", "s3-website", "elb", "es", "execute-api", "lambda-url", "elasticbeanstalk", "redshift",
    "docdb", "neptune", "kafka", "mq", "dkr", "ecr", "eks", "aoss", "memorydb", "dax", "elasticache",
}
_AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
# AWS public service endpoints (``email-smtp.us-east-1.amazonaws.com``, ``sts.amazonaws.com``).
_AWS_PUBLIC_FIRST = {
    "email-smtp", "email", "sts", "sqs", "sns", "s3", "dynamodb", "ec2", "logs", "monitoring", "secretsmanager",
    "kms", "ssm", "iam", "lambda", "cloudformation", "route53", "sesv2", "ses", "ecs", "ecr", "eks", "athena",
    "glue", "kinesis", "firehose", "events", "states", "cognito-idp", "cognito-identity", "apigateway", "acm",
    "elasticloadbalancing", "autoscaling", "cloudwatch", "xray", "batch", "codebuild", "codecommit", "s3-accesspoint",
}
PROVIDER_TAIL = re.compile(
    r"\.(?:[a-z0-9\-]+\.)*(?:amazonaws\.com|windows\.net|azure\.(?:com|net)|azurewebsites\.net|azurecr\.io|azure-api\.net"
    r"|supabase\.co|psdb\.cloud|mongodb\.net|firebaseio\.com|firebaseapp\.com|web\.app|herokuapp\.com|cloudfront\.net"
    r"|sentry\.io|atlassian\.net|myshopify\.com|okta\.com|auth0\.com|vercel\.app|netlify\.app|pages\.dev|workers\.dev"
    r"|appspot\.com|run\.app|cloudfunctions\.net|digitaloceanspaces\.com|ondigitalocean\.app|upstash\.io|neon\.tech"
    r"|sharepoint\.com|zendesk\.com|salesforce\.com)(?![A-Za-z0-9\-.])",
    re.IGNORECASE,
)

_HOST_KEY_WORDS = {
    "host", "hostname", "hosts", "server", "servers", "endpoint", "endpoints", "url", "urls", "uri", "uris", "dsn",
    "domain", "domains", "broker", "brokers", "address", "addr", "ip", "ips", "fqdn", "origin", "bastion", "gateway",
    "proxy", "nameserver", "nameservers", "dns", "mx", "registry", "cluster", "nodes", "seeds", "peers", "smarthost",
    "relay", "upstream", "backend", "backends", "mirror", "remote",
}
_GENERIC_HOST_KEYS = {"host", "hostname", "hosts", "server", "url", "uri", "domain", "address", "addr", "ip",
                      "endpoint", "fqdn", "dsn", "urls", "servers", "endpoints"}
_VERSION_WORDS = {"version", "ver", "release", "build", "tag", "revision", "rev", "semver"}
_BUCKET_WORDS = {"bucket", "buckets"}

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

FQDN = re.compile(
    r"(?<![\w.\-@/\\$])(?P<host>(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9])?\.)+(?P<tld>[a-z][a-z0-9\-]{1,62}))\.?(?![\w\-]|\.[a-z0-9])",
    re.IGNORECASE,
)
IPV4 = re.compile(r"(?<![\w.])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?P<cidr>/\d{1,2})?(?![\w.]|\.\d)")
IPV4_WILDCARD = re.compile(r"(?<![\w.])(?P<net>\d{1,3}(?:\.\d{1,3}){0,2})\.%(?![\w])")
IPV6 = re.compile(r"(?<![\w:.])(?P<ip>(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?P<cidr>/\d{1,3})?(?![\w:.])")
# userinfo may contain '@' (split at the last '@' before the host, like the drivers do)
URL_AUTH = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://(?:[^\s/'\"`?#]*@)?(?P<host>\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.\-_%]+)")
S3_URL = re.compile(r"\b(?:s3|gs|s3a|s3n)://(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?=[/'\"`\s]|$)")
DSN_HOST = re.compile(r"(?i)(?:^|[\s;\"'(,])(?:host|hostaddr|server|data source|address|addr)\s*=\s*(?:tcp:)?(?P<host>[^;\s'\",)]+)")
CLI_HOST = re.compile(r"(?:^|\s)(?:-h|--host)(?:\s+|=)(?P<host>[A-Za-z0-9.\-:\[\]]+)", re.MULTILINE)
SQL_GRANT_HOST = re.compile(r"'[^'\n]{0,64}'@'(?P<host>[^'\n]{1,255})'")
ARN_ACCOUNT = re.compile(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:(?P<account>\d{12}):")
EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9._%+\-]+@(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})\b")
_KV = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,80})[\"']?[ \t]*(?::=|=>|=|:)[ \t]*(?:[rRbBuUfF]{0,2})"
    r"(?:(?P<q>[\"'`])(?P<qv>(?:\\.|(?!(?P=q))[^\\\n]){1,2048})(?P=q)|(?P<bv>[^\s\"'`;,#\[\]{}()]{1,2048}))"
)
_CALL_KV = re.compile(r"\b(?:define|put|set|setenv|putenv)\s*\(\s*(?P<kq>[\"'])(?P<key>[^\"'\n]{1,80})(?P=kq)\s*,\s*(?P<q>[\"'`])(?P<qv>[^\"'`\n]{1,2048})(?P=q)")
_CONCAT_RHS = re.compile(r"(?P<key>\$?[A-Za-z_]\w*)[\"']?[ \t]*(?:=>|=|:)[ \t]*(?P<rhs>['\"][^;\n]*?['\"](?:[ \t]*[.+][ \t]*['\"][^;\n]*?['\"])+)(?=[ \t]*[;,)\]\n])")
_XML_KV = re.compile(r"<(?P<key>[A-Za-z_][\w.\-]{0,80})>(?P<qv>[^<>\n]{1,2048})</(?P=key)>")


@dataclass(frozen=True)
class InfraHit:
    file: str
    start: int
    end: int
    line: int
    value: str  # exact replaced text (host labels, address, bucket, ...)
    kind: str   # host | domain | ip | net | bucket | account | project
    key: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def public_domains() -> frozenset[str]:
    text = resources.files("ai_safe").joinpath("data/public_domains.txt").read_text(encoding="utf-8")
    return frozenset(ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))


def _under(host: str, domains) -> bool:
    """``host`` equals or is a subdomain of one of ``domains`` (a set or any iterable)."""
    if not isinstance(domains, (set, frozenset)):
        domains = set(domains)
    labels = host.split(".")
    return any(".".join(labels[i:]) in domains for i in range(len(labels)))


def registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def known_tld(tld: str) -> bool:
    t = tld.lower()
    return t in INTERNAL_TLDS or t in _GTLDS or (len(t) == 2 and t.isalpha())


def is_host_key(key: str | None) -> bool:
    if not key or is_sensitive_key(key):
        return False
    return bool(set(key_words(key)) & _HOST_KEY_WORDS)


def _generic_key(key: str | None) -> bool:
    words = key_words(key or "")
    return not words or (len(words) == 1 and words[0] in _GENERIC_HOST_KEYS)


def _version_key(key: str | None) -> bool:
    return bool(set(key_words(key or "")) & _VERSION_WORDS)


def provider_split(host: str) -> tuple[int, bool] | None:
    """For a provider host: (length of the customer part, public). None when not a provider host."""
    h = host.lower()
    for sfx in PROVIDER_SUFFIXES:
        if h.endswith(sfx) and len(h) > len(sfx):
            return len(h) - len(sfx), False
    if h == "amazonaws.com" or h.endswith(".amazonaws.com"):
        labels = h.split(".")[:-2]
        if not labels or labels[0] in _AWS_PUBLIC_FIRST:
            return 0, True
        for i, lab in enumerate(labels):
            if lab in _AWS_SERVICE_LABELS or _AWS_REGION.match(lab):
                if i == 0:
                    return 0, True
                return len(".".join(labels[:i])), False
        return 0, True
    return None


def classify_ip(text: str, mode: str) -> str | None:
    """'ip' when the address must be replaced in ``mode`` (private | all), else None."""
    try:
        addr = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or str(addr) == "255.255.255.255":
        return None
    v4 = isinstance(addr, ipaddress.IPv4Address)
    doc = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
           ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("198.18.0.0/15")) if v4 else (
        ipaddress.ip_network("2001:db8::/32"),)
    if any(addr in n for n in doc):
        return None  # documentation / benchmark ranges (and ai-safe's own pseudonyms)
    cgnat = v4 and addr in ipaddress.ip_network("100.64.0.0/10")
    private = addr.is_private or addr.is_link_local or cgnat
    if mode == "all" or (mode == "private" and private):
        return "ip"
    return None


def _regions(text: str, rel: str) -> "_Spans | None":
    """Spans of string literals and comments in a source file; None = whole text."""
    if file_kind(rel) != "source" or rel.lower().endswith((".md", ".txt", ".rst", ".sql", ".html", ".htm", ".xml")):
        return None
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c and not (text[j] == "\n" and c != "`"):
                j += 2 if text[j] == "\\" else 1
            spans.append((i + 1, min(j, n)))
            i = j + 1
            continue
        if text.startswith("//", i) or c == "#" or (text.startswith("--", i) and (i == 0 or text[i - 1] in " \t\n")):
            if c == "#" and i + 1 < n and text[i + 1] == "[":
                i += 1
                continue  # PHP / Rust attribute
            j = text.find("\n", i)
            j = n if j == -1 else j
            spans.append((i, j))
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            spans.append((i, j))
            i = j
            continue
        i += 1
    return _Spans(spans)


class _Spans:
    """Sorted, non-overlapping literal / comment spans with O(log n) lookup."""

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        self.spans = sorted(spans)
        self.starts = [a for a, _ in self.spans]

    def contains(self, s: int, e: int) -> bool:
        i = bisect.bisect_right(self.starts, s) - 1
        return i >= 0 and self.spans[i][0] <= s and e <= self.spans[i][1]


def _inside(spans: "_Spans | None", s: int, e: int) -> bool:
    return True if spans is None else spans.contains(s, e)


class _LineIndex:
    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class InfraDetector:
    def __init__(self, cfg: InfrastructureConfig) -> None:
        self.cfg = cfg
        self.keep = frozenset(public_domains() | set(cfg.keep_domains))
        self.org: set[str] = set(cfg.org_domains)

    # -- host classification ------------------------------------------------

    def _host_hit(self, rel, text, lines, s, e, host, key, strong) -> InfraHit | None:
        """Hit for an FQDN occurrence at ``text[s:e]`` (``host`` lowercased), or None."""
        if not self.cfg.hostnames:
            return None
        labels = host.split(".")
        tld = labels[-1]
        if len(labels) < 2:
            return None
        if tld in RESERVED_TLDS or host in RESERVED_DOMAINS or _under(host, RESERVED_DOMAINS) or host == "localhost":
            return None
        if tld in FILE_EXTENSIONS and not _under(host, self.org) and not is_host_key(key):
            return None
        if all(lab.isdigit() for lab in labels):
            return None
        org = _under(host, self.org)
        if not org and _under(host, self.cfg.keep_domains):
            return None
        split = provider_split(host)
        if split is not None:
            n, public = split
            if public or n == 0:
                return None
            return InfraHit(rel, s, s + n, lines.line_of(s), text[s:s + n], "host", None if _generic_key(key) else key)
        if not org and _under(host, self.keep):
            return None
        internal = tld in INTERNAL_TLDS or ".".join(labels[-2:]) in ("home.arpa", "cluster.local")
        if not (org or internal or strong):
            return None  # a bare FQDN: only when it belongs to the organisation
        if not (org or internal) and labels[0] in _GTLDS and len(labels) >= 3 and not known_tld(tld):
            return None  # reverse-DNS package name (com.company.app)
        return self._make(rel, text, lines, s, e, host, key)

    def _make(self, rel, text, lines, s, e, host, key) -> InfraHit:
        key = None if _generic_key(key) else key
        if self.cfg.scope == "domain":
            reg = registrable(host)
            if reg != host:
                off = len(host) - len(reg)
                return InfraHit(rel, s + off, e, lines.line_of(s), text[s + off:e], "domain", None)
            return InfraHit(rel, s, e, lines.line_of(s), text[s:e], "domain", key)
        return InfraHit(rel, s, e, lines.line_of(s), text[s:e], "host", key)

    def _ip_hit(self, rel, text, lines, s, e, value, key, cidr: str | None = None) -> InfraHit | None:
        if self.cfg.ip_addresses == "none" or _version_key(key):
            return None
        if classify_ip(value, self.cfg.ip_addresses) is None:
            return None
        kind = "net" if cidr else "ip"
        return InfraHit(rel, s, e, lines.line_of(s), text[s:e], kind, None if _generic_key(key) else key)

    # -- value scanning -----------------------------------------------------

    def _scan_value(self, rel, text, lines, vs, ve, key, strong, out) -> None:
        """Every host / IP inside ``text[vs:ve]``."""
        seg = text[vs:ve]
        if _version_key(key):
            return
        for m in URL_AUTH.finditer(seg):
            host = m.group("host")
            if not host.startswith("["):
                fm = FQDN.fullmatch(host)
                if fm:
                    hit = self._host_hit(rel, text, lines, vs + m.start("host"), vs + m.end("host"), host.lower(), key, strong)
                    if hit:
                        out.append(hit)
        for m in IPV4.finditer(seg):
            parts = m.group("ip").split(".")
            if any(int(p) > 255 for p in parts):
                continue
            hit = self._ip_hit(rel, text, lines, vs + m.start("ip"), vs + m.end("ip"), m.group("ip"), key, m.group("cidr"))
            if hit:
                out.append(hit)
        for m in IPV6.finditer(seg):
            if m.group("ip").count(":") >= 2:
                hit = self._ip_hit(rel, text, lines, vs + m.start("ip"), vs + m.end("ip"), m.group("ip"), key, m.group("cidr"))
                if hit:
                    out.append(hit)
        for m in FQDN.finditer(seg):
            host = m.group("host").lower()
            hit = self._host_hit(rel, text, lines, vs + m.start("host"), vs + m.end("host"), host, key, strong)
            if hit:
                out.append(hit)
        if strong and self.cfg.hostnames:
            # single-label hosts only when listed in org_domains
            v = seg.strip()
            if re.fullmatch(r"[A-Za-z0-9\-]+", v) and v.lower() in self.org:
                out.append(InfraHit(rel, vs, ve, lines.line_of(vs), v, "host", None if _generic_key(key) else key))

    def _strong(self, rel: str, text: str) -> list[InfraHit]:
        lines = _LineIndex(text)
        spans = _regions(text, rel)
        out: list[InfraHit] = []
        for rx in (_KV, _CALL_KV, _XML_KV):
            for m in rx.finditer(text):
                key = m.group("key")
                grp = "qv" if m.group("qv") is not None else "bv"
                if m.group(grp) is None:
                    continue
                vs, ve = m.span(grp)
                if spans is not None and grp == "bv":
                    continue  # unquoted values in source code are expressions
                if is_host_key(key):
                    self._scan_value(rel, text, lines, vs, ve, key, True, out)
                elif self.cfg.buckets and set(key_words(key)) & _BUCKET_WORDS:
                    v = m.group(grp).strip()
                    if re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", v) and not _version_key(key):
                        out.append(InfraHit(rel, vs, ve, lines.line_of(vs), text[vs:ve], "bucket",
                                            None if key_words(key) == ["bucket"] else key))
                elif self.cfg.cloud_resource_ids and key_words(key)[-2:] == ["project", "id"]:
                    v = m.group(grp).strip()
                    if re.fullmatch(r"[a-z][a-z0-9\-]{4,28}[a-z0-9]", v):
                        out.append(InfraHit(rel, vs, ve, lines.line_of(vs), text[vs:ve], "project", None))
                else:
                    # whole-value IP literal (``$x = '10.0.0.5'``)
                    v = m.group(grp)
                    if IPV4.fullmatch(v) or (v.count(":") >= 2 and IPV6.fullmatch(v)):
                        self._scan_value(rel, text, lines, vs, ve, key, True, out)
        for rx in (URL_AUTH, DSN_HOST, CLI_HOST, SQL_GRANT_HOST):
            for m in rx.finditer(text):
                s, e = m.span("host")
                if not _inside(spans, s, e):
                    continue
                host = m.group("host")
                if rx is SQL_GRANT_HOST:
                    wm = IPV4_WILDCARD.fullmatch(host)
                    if wm and self.cfg.ip_addresses != "none":
                        net = wm.group("net")
                        if classify_ip(net + ".0" * (4 - len(net.split("."))), self.cfg.ip_addresses):
                            out.append(InfraHit(rel, s, s + len(net), lines.line_of(s), net, "net"))
                        continue
                self._scan_value(rel, text, lines, s, e, None, True, out)
        if self.cfg.buckets:
            for m in S3_URL.finditer(text):
                s, e = m.span("bucket")
                if _inside(spans, s, e):
                    out.append(InfraHit(rel, s, e, lines.line_of(s), m.group("bucket"), "bucket"))
        if self.cfg.cloud_resource_ids:
            for m in ARN_ACCOUNT.finditer(text):
                s, e = m.span("account")
                out.append(InfraHit(rel, s, e, lines.line_of(s), m.group("account"), "account"))
        out.extend(self._concat(rel, text, lines, True))
        # internal pseudo-TLDs and org domains anywhere in literals / comments / config
        for m in FQDN.finditer(text):
            host = m.group("host").lower()
            s, e = m.span("host")
            if not _inside(spans, s, e):
                continue
            labels = host.split(".")
            if labels[-1] in INTERNAL_TLDS or _under(host, self.org):
                hit = self._host_hit(rel, text, lines, s, e, host, None, True)
                if hit:
                    out.append(hit)
        return out

    def _concat(self, rel: str, text: str, lines: _LineIndex, strong: bool) -> list[InfraHit]:
        """Hosts built by constant concatenation (``'db' . '.company.net'``)."""
        out: list[InfraHit] = []
        if file_kind(rel) != "source":
            return out
        for m in _CONCAT_RHS.finditer(text):
            folded = fold_literal(text, *m.span("rhs"))
            if not folded or "'" not in folded[0] and '"' not in folded[0]:
                continue
            value = re.sub(r"['\"]\s*[.+]\s*['\"]", "", folded[0])
            fm = FQDN.fullmatch(value)
            if not fm:
                continue
            host = value.lower()
            key = m.group("key")
            keyed = is_host_key(key)
            if not (keyed or _under(host, self.org) or host.rsplit(".", 1)[-1] in INTERNAL_TLDS) or keyed != strong:
                continue
            hit = self._host_hit(rel, text, lines, folded[1], folded[2], host, key if keyed else None, keyed)
            if hit:
                out.append(InfraHit(rel, folded[1], folded[2], hit.line, text[folded[1]:folded[2]], "host", hit.key))
        return out

    def _weak(self, rel: str, text: str) -> list[InfraHit]:
        lines = _LineIndex(text)
        spans = _regions(text, rel)
        out: list[InfraHit] = self._concat(rel, text, lines, False)
        for m in FQDN.finditer(text):
            host = m.group("host").lower()
            s, e = m.span("host")
            if not _inside(spans, s, e) or not _under(host, self.org):
                continue
            hit = self._host_hit(rel, text, lines, s, e, host, None, False)
            if hit:
                out.append(hit)
        return out

    def detect(self, texts: dict[str, str]) -> list[InfraHit]:
        if not self.cfg.enabled:
            return []
        strong: list[InfraHit] = []
        for rel, text in sorted(texts.items()):
            strong.extend(self._strong(rel, text))
        # Organisation domains: registrable domains of strong (non-provider) hosts, and email domains.
        for h in strong:
            if h.kind == "host" and "." in h.value and not provider_split(h.value.lower()):
                reg = registrable(h.value.lower())
                if not _under(reg, self.keep):
                    self.org.add(reg)
        for rel, text in texts.items():
            for m in EMAIL_DOMAIN.finditer(text):
                d = m.group("domain").lower()
                if known_tld(d.rsplit(".", 1)[-1]) and d.rsplit(".", 1)[-1] not in FILE_EXTENSIONS \
                        and not _under(d, self.keep) and not _under(d, RESERVED_DOMAINS) and d.rsplit(".", 1)[-1] not in RESERVED_TLDS:
                    self.org.add(registrable(d))
        weak: list[InfraHit] = []
        for rel, text in sorted(texts.items()):
            weak.extend(self._weak(rel, text))
        return _dedupe(strong + weak)


def _dedupe(hits: list[InfraHit]) -> list[InfraHit]:
    """One hit per span; a longer span wins over a contained one."""
    hits = sorted(set(hits), key=lambda h: (h.file, h.start, -(h.end - h.start), h.key is None))
    out: list[InfraHit] = []
    for h in hits:
        if out and out[-1].file == h.file and h.start < out[-1].end:
            continue
        out.append(h)
    return out


def detect_infra(texts: dict[str, str], cfg: InfrastructureConfig) -> list[InfraHit]:
    return InfraDetector(cfg).detect(texts)


# ---------------------------------------------------------------------------
# Pseudonyms (mode: pseudonym)
# ---------------------------------------------------------------------------

def pseudonym(kind: str, fingerprint: str, value: str) -> str:
    """Deterministic, syntactically valid stand-in that never resolves."""
    fp = fingerprint
    if kind == "host":
        return f"h-{fp[:6]}.d-{fp[6:12]}.invalid" if "." in value else f"h-{fp[:6]}"
    if kind == "domain":
        return f"d-{fp[:6]}.invalid"
    if kind in ("ip", "net"):
        try:
            addr = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            n = int(fp[:8], 16)
            parts = value.split(".")
            base = [198, 18 + (n >> 16) % 2, (n >> 8) % 256, n % 256]
            return ".".join(str(b) for b in base[: len(parts)])
        n = int(fp[:8], 16)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.18.0.0")) + n % (1 << 17)))
        return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("2001:db8::")) + int(fp[:16], 16) % (1 << 96)))
    if kind == "bucket":
        return f"bucket-{fp[:8]}"
    if kind == "project":
        return f"project-{fp[:8]}"
    if kind == "account":
        return "0000" + str(int(fp[:10], 16) % 10**8).zfill(8)
    return f"x-{fp[:8]}"


PSEUDONYM_RE = re.compile(
    r"\bh-[0-9a-f]{6}(?:\.d-[0-9a-f]{6}\.invalid)?\b|\bd-[0-9a-f]{6}\.invalid\b|\b198\.1[89]\.\d{1,3}\.\d{1,3}\b"
    r"|\b2001:db8:[0-9a-fA-F:]*|\bbucket-[0-9a-f]{8}\b|\bproject-[0-9a-f]{8}\b|\b0000\d{8}\b"
)


# ---------------------------------------------------------------------------
# Leftover sweep (verify)
# ---------------------------------------------------------------------------

def leftover_infra(text: str, rel: str, cfg: InfrastructureConfig, org: set[str]) -> list[int]:
    """Lines that still hold an internal FQDN (internal pseudo-TLD or org
    domain) or a private IP address in a literal / comment / config value."""
    if not cfg.enabled:
        return []
    det = InfraDetector(cfg)
    det.org |= org
    hits = det._strong(rel, text) + det._weak(rel, text)
    return sorted({h.line for h in hits})
