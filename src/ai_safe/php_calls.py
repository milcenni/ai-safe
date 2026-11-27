"""Credentials passed positionally to PHP calls.

Covers database connections (``new PDO``, ``mysqli_connect``, ``new mysqli``,
``mysql_connect``, ``oci_connect``, ``odbc_connect``, ``pg_connect`` ...),
other services (FTP, LDAP, IMAP/POP3, SSH, Redis, AMQP/RabbitMQ, Memcached
SASL, AWS SDK credentials as used for S3/MinIO, cURL ``CURLOPT_USERPWD``) and
connect-like wrappers such as ``$this->db->connect('db', 'user', 'pw')`` or
``custom_connect('user', 'pw')``. Only string literals passed directly in the
call are found; values that reach a call through variables, constants or
other functions are not traced (see README "Security limitations").

Because the call context identifies the value, short low-entropy passwords
are reported too. Usernames are reported only next to a reported password,
and never when they are common defaults (``root``, ``postgres``, ...) or
host-like: redaction replaces long values everywhere, so those must never
become placeholders.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from ai_safe.models import Category

PHP_SUFFIXES = (".php", ".phtml", ".inc", ".php3", ".php4", ".php5", ".php7", ".php8", ".phps")


@dataclass(frozen=True)
class Sink:
    user: int | None  # 1-based position of the user / access key, if any
    pw: int  # 1-based position of the password / secret
    service: str
    category: Category = Category.PASSWORD
    method_only: bool = False  # only as ``->name(`` / ``::name(``
    min_args: int = 1
    user_key: str = ""
    pw_key: str = ""

    @property
    def keys(self) -> tuple[str, str]:
        return (self.user_key or f"{self.service}_username", self.pw_key or f"{self.service}_password")


_DB = Category.DATABASE_CREDENTIAL


def _db(user: int | None, pw: int, **kw) -> Sink:
    return Sink(user, pw, "db", _DB, **kw)


# Lowercased call name -> sink. ``new name`` entries are constructors.
_SINKS: dict[str, Sink] = {
    # databases
    "new pdo": _db(2, 3),
    "new mysqli": _db(2, 3),
    "mysqli_connect": _db(2, 3),
    "mysqli_real_connect": _db(3, 4),
    "real_connect": _db(2, 3, method_only=True),
    "change_user": _db(1, 2, method_only=True, min_args=2),
    "mysqli_change_user": _db(2, 3),
    "mysql_connect": _db(2, 3),
    "mysql_pconnect": _db(2, 3),
    "mssql_connect": _db(2, 3),
    "mssql_pconnect": _db(2, 3),
    "sybase_connect": _db(2, 3),
    "odbc_connect": _db(2, 3),
    "odbc_pconnect": _db(2, 3),
    "db2_connect": _db(2, 3),
    "db2_pconnect": _db(2, 3),
    "ibase_connect": _db(2, 3),
    "ibase_pconnect": _db(2, 3),
    "oci_connect": _db(1, 2),
    "oci_pconnect": _db(1, 2),
    "oci_new_connect": _db(1, 2),
    # file transfer, directory, mail, shell
    "ftp_login": Sink(2, 3, "ftp"),
    "ldap_bind": Sink(2, 3, "ldap", user_key="ldap_bind_dn"),
    "ldap_sasl_bind": Sink(2, 3, "ldap", user_key="ldap_bind_dn"),
    "imap_open": Sink(2, 3, "mail"),
    "ssh2_auth_password": Sink(2, 3, "ssh"),
    # ``$pop3->login``, ``$imap->login``, phpseclib ``$ssh->login`` / ``$sftp->login``
    "login": Sink(1, 2, "login", method_only=True, min_args=2),
    # message queues and caches
    "new amqpstreamconnection": Sink(3, 4, "amqp"),
    "new amqpsslconnection": Sink(3, 4, "amqp"),
    "new amqplazyconnection": Sink(3, 4, "amqp"),
    "new amqplazysslconnection": Sink(3, 4, "amqp"),
    "new amqpsocketconnection": Sink(3, 4, "amqp"),
    "setsaslauthdata": Sink(1, 2, "memcached", method_only=True, min_args=2),
    # AWS SDK credentials (S3, MinIO and other S3-compatible stores)
    "new credentials": Sink(1, 2, "aws", Category.CLOUD_CREDENTIAL, min_args=2,
                            user_key="aws_access_key_id", pw_key="aws_secret_access_key"),
}
# Redis ``->auth('pw')``, ``->auth('user', 'pw')``, ``->auth(['user', 'pw'])``.
_REDIS_AUTH = "auth"
# libpq connection string in the first argument.
_CONNINFO = {"pg_connect", "pg_pconnect"}
# Network/protocol connects whose arguments are not credentials.
_NOT_CREDENTIAL = {
    "socket_connect", "ftp_connect", "ftp_ssl_connect", "ssh2_connect", "ldap_connect",
    "stream_socket_client", "disconnect", "reconnect", "ssh_connect",
}

_CALL = re.compile(
    r"(?i)(?:(?P<new>\bnew\s+\\?)|(?P<op>->|::)|(?<![\w$>:]))"
    r"(?:[A-Za-z_]\w*\\)*(?P<name>[A-Za-z_]\w*)\s*\("
)
_CONNECT_NAME = re.compile(r"(?i)^\w*connect(?:v?\d+)?$")
_CONNINFO_PW = re.compile(r"(?:^|\s)password\s*=\s*(?:'(?P<q>(?:\\.|[^'\\])*)'|(?P<b>[^\s']+))")
_USERPWD = re.compile(
    r"\bCURLOPT_USERPWD\s*(?:,|=>)\s*(?P<q>['\"])(?P<user>[^'\":\n\\$]*):"
    r"(?P<pw>(?:\\.|(?!(?P=q))[^\\\n])+)(?P=q)"
)

_DEFAULT_USERS = {
    "root", "admin", "administrator", "sa", "postgres", "mysql", "user", "sys", "system",
    "oracle", "dbo", "guest", "test", "www-data", "app", "web", "default", "username",
}
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^\[?[0-9a-fA-F:]+:[0-9a-fA-F:]*\]?$")
_HOST_RE = re.compile(r"(?i)^(?:localhost|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})(?::\d+)?$")
_NUM_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")

_MAX_ARGS_SPAN = 4000
_GENERIC = Sink(None, 0, "connect")  # placeholder keys for connect-like wrappers


@dataclass(frozen=True)
class Arg:
    kind: str  # "str" (plain string literal), "num", "array", "other", "empty"
    value: str = ""
    start: int = 0  # str: span of the content inside the quotes; array: the '['
    end: int = 0


@dataclass(frozen=True)
class CallMatch:
    rule_id: str
    role: str  # "user" or "password"
    start: int
    end: int
    secret: str
    category: Category
    key: str


def is_php(path: str) -> bool:
    return PurePosixPath(path).suffix.casefold() in PHP_SUFFIXES


def parse_args(text: str, open_idx: int) -> list[Arg] | None:
    """Split the list starting at ``text[open_idx]`` (``(`` or ``[``).
    Returns None when the matching closer is not found nearby."""
    closer = ")" if text[open_idx] == "(" else "]"
    args: list[Arg] = []
    i, n = open_idx + 1, min(len(text), open_idx + _MAX_ARGS_SPAN)
    seg_start, depth = i, 0
    literals: list[tuple[str, int, int]] = []  # (quote, content start, content end)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            if depth == 0:
                literals.append((c, i + 1, j))
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                if c != closer:
                    return None
                args.append(_classify(text, seg_start, i, literals))
                if args[-1].kind == "empty":
                    args.pop()  # ``f()`` or a trailing comma
                return args
            depth -= 1
        elif c == "," and depth == 0:
            args.append(_classify(text, seg_start, i, literals))
            seg_start, literals = i + 1, []
        i += 1
    return None


def _classify(text: str, start: int, end: int, literals: list[tuple[str, int, int]]) -> Arg:
    seg = text[start:end].strip()
    if not seg:
        return Arg("empty")
    if len(literals) == 1:
        q, s, e = literals[0]
        if seg == text[s - 1:e + 1]:
            value = text[s:e]
            if q == '"' and "$" in value:
                return Arg("other")  # interpolated
            return Arg("str", value, s, e)
    if _NUM_RE.match(seg):
        return Arg("num", seg)
    if seg.startswith("[") and seg.endswith("]"):
        return Arg("array", seg, start + (len(text[start:end]) - len(text[start:end].lstrip())))
    return Arg("other")


def _hostish(v: str) -> bool:
    return bool(_IP_RE.match(v) or _HOST_RE.match(v))


def find_call_credentials(text: str) -> Iterator[CallMatch]:
    for m in _USERPWD.finditer(text):
        yield from _userpwd(m)
    for m in _CALL.finditer(text):
        name = m.group("name").lower()
        if name in _NOT_CREDENTIAL:
            continue
        is_method = m.group("op") is not None
        sink = _SINKS.get(f"new {name}") if m.group("new") else _SINKS.get(name)
        if sink is not None and sink.method_only and not is_method:
            sink = None
        if sink is None and m.group("new"):
            continue
        if sink is None and name in _CONNINFO and not is_method:
            args = parse_args(text, m.end() - 1)
            if args and args[0].kind == "str":
                yield from _conninfo(args[0])
            continue
        if sink is None and name == _REDIS_AUTH and is_method:
            args = parse_args(text, m.end() - 1)
            if args:
                yield from _redis_auth(text, args)
            continue
        if sink is None and not _CONNECT_NAME.match(name):
            continue
        args = parse_args(text, m.end() - 1)
        if not args:
            continue
        if sink is not None:
            if len(args) >= sink.min_args:
                rule = "php-db-connect" if sink.category is _DB else "php-auth-call"
                yield from _emit(args, sink.user, sink.pw, rule, sink, generic=False)
            continue
        # Unknown connect-like wrapper: (user, pw) or (host, user, pw, ...).
        if any(a.kind == "num" for a in args[:3]) or len(args) < 2:
            continue
        if len(args) == 2 and args[0].kind == "str" and _hostish(args[0].value):
            continue  # (host, db) or (host, user): no password position
        user_pos, pw_pos = (1, 2) if len(args) == 2 else (2, 3)
        yield from _emit(args, user_pos, pw_pos, "php-connect-call", _GENERIC, generic=True)


def _usable(a: Arg, generic: bool) -> bool:
    from ai_safe.detectors import _trivial_value  # local import: avoid cycle

    return a.kind == "str" and bool(a.value.strip()) and not _trivial_value(a.value) and not (generic and _hostish(a.value))


def _user_ok(a: Arg, generic: bool) -> bool:
    return _usable(a, generic) and a.value.lower() not in _DEFAULT_USERS and not _hostish(a.value)


def _emit(args: list[Arg], user_pos: int | None, pw_pos: int, rule_id: str, sink: Sink, generic: bool) -> Iterator[CallMatch]:
    if pw_pos > len(args) or not _usable(pw := args[pw_pos - 1], generic):
        return
    user_key, pw_key = sink.keys
    yield CallMatch(rule_id, "password", pw.start, pw.end, pw.value, sink.category, pw_key)
    if user_pos and user_pos <= len(args) and _user_ok(u := args[user_pos - 1], generic):
        yield CallMatch(rule_id, "user", u.start, u.end, u.value, sink.category, user_key)


_REDIS = Sink(1, 2, "redis")


def _redis_auth(text: str, args: list[Arg]) -> Iterator[CallMatch]:
    if len(args) == 1 and args[0].kind == "array":
        items = parse_args(text, args[0].start)
        if not items or len(items) > 2:
            return
        args = items
    if len(args) == 1:
        yield from _emit(args, None, 1, "php-auth-call", _REDIS, generic=False)
    elif len(args) == 2:
        yield from _emit(args, 1, 2, "php-auth-call", _REDIS, generic=False)


def _userpwd(m: re.Match[str]) -> Iterator[CallMatch]:
    pw = Arg("str", m.group("pw"), *m.span("pw"))
    user = Arg("str", m.group("user"), *m.span("user"))
    if m.group("q") == '"' and "$" in pw.value:
        return
    yield from _emit([user, pw], 1, 2, "php-auth-call", Sink(1, 2, "http"), generic=False)


def _conninfo(arg: Arg) -> Iterator[CallMatch]:
    from ai_safe.detectors import _trivial_value

    user_key, pw_key = _db(None, 1).keys
    for m in _CONNINFO_PW.finditer(arg.value):
        group = "q" if m.group("q") is not None else "b"
        value = m.group(group)
        if value and not _trivial_value(value):
            s, e = m.span(group)
            yield CallMatch("php-db-connect", "password", arg.start + s, arg.start + e, value, _DB, pw_key)
