"""Built-in detection engine.

Runs in addition to Gitleaks (defence in depth) and is also used by the
redaction engine to re-scan sanitized output. Every match carries exact
character offsets so the redaction engine can replace precisely what was
detected. Matches that cannot be bounded precisely are marked ``exact=False``;
the sanitizer then fails closed and excludes the file.

Pattern matching cannot find every secret (see README "Detection limitations").
"""

from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from ai_safe.classifier import categorize, file_kind, is_password_key, is_sensitive_key, key_words
from ai_safe.config import CustomRule
from ai_safe.models import Category
from ai_safe.php_calls import find_call_credentials, is_php
from ai_safe.security import PLACEHOLDER_NAME_RE, is_placeholder_value


@dataclass(eq=False)
class RawMatch:
    rule_id: str
    category: Category
    start: int
    end: int
    line: int
    end_line: int
    key: str | None = None
    exact: bool = True
    engine: str = "builtin"
    secret: str = field(default="", repr=False)


@dataclass(frozen=True)
class TokenRule:
    id: str
    regex: re.Pattern[str]
    category: Category
    group: str | int = "secret"


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


# Provider-specific token formats. Each has a named group ``secret``.
TOKEN_RULES: tuple[TokenRule, ...] = (
    TokenRule("aws-access-key-id", _r(r"\b(?P<secret>(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b"), Category.CLOUD_CREDENTIAL),
    TokenRule("aws-secret-access-key", _r(r"(?i)aws.{0,24}?(?:secret|private).{0,24}?['\"\s:=>]+(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"), Category.CLOUD_CREDENTIAL),
    TokenRule("gcp-api-key", _r(r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), Category.CLOUD_CREDENTIAL),
    TokenRule("azure-storage-key", _r(r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{86}==)"), Category.CLOUD_CREDENTIAL),
    TokenRule("github-token", _r(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{36,255})\b"), Category.ACCESS_TOKEN),
    TokenRule("github-fine-grained-pat", _r(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{40,255})\b"), Category.ACCESS_TOKEN),
    TokenRule("gitlab-token", _r(r"\b(?P<secret>gl(?:pat|dt|ptt|rt)-[A-Za-z0-9_\-]{20,})\b"), Category.ACCESS_TOKEN),
    TokenRule("slack-token", _r(r"\b(?P<secret>xox[abeoprs]-[A-Za-z0-9-]{10,})\b"), Category.ACCESS_TOKEN),
    TokenRule("slack-webhook", _r(r"(?P<secret>https://hooks\.slack\.com/services/[A-Za-z0-9+/]{30,})"), Category.ACCESS_TOKEN),
    TokenRule("npm-token", _r(r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b"), Category.ACCESS_TOKEN),
    TokenRule("pypi-token", _r(r"\b(?P<secret>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"), Category.ACCESS_TOKEN),
    TokenRule("anthropic-api-key", _r(r"\b(?P<secret>sk-ant-[A-Za-z0-9_\-]{20,})"), Category.API_KEY),
    TokenRule("openai-api-key", _r(r"\b(?P<secret>sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})"), Category.API_KEY),
    TokenRule("stripe-key", _r(r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), Category.API_KEY),
    TokenRule("sendgrid-api-key", _r(r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), Category.API_KEY),
    TokenRule("twilio-api-key", _r(r"\b(?P<secret>SK[0-9a-fA-F]{32})\b"), Category.API_KEY),
    TokenRule("mailgun-api-key", _r(r"\b(?P<secret>key-[0-9a-zA-Z]{32})\b"), Category.API_KEY),
    TokenRule("jwt", _r(r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), Category.ACCESS_TOKEN),
    TokenRule("bearer-token", _r(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{20,}=*)"), Category.ACCESS_TOKEN),
    TokenRule("url-credentials", _r(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@'\"`]{0,128}:(?P<secret>[^\s@'\"`/]{1,256})@[^\s'\"`]+"), Category.DATABASE_CREDENTIAL),
    TokenRule("url-username-token", _r(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://(?P<secret>[A-Za-z0-9_\-]{20,256})(?::[^\s@'\"`/]*)?@[^\s'\"`]+"), Category.ACCESS_TOKEN),
    TokenRule("basic-auth-header", _r(r"(?i)\bbasic\s+(?P<secret>[A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])"), Category.PASSWORD),
    TokenRule("query-password", _r(r"(?i)[?&;](?:password|passwd|pwd|pass|secret|token|api_?key|access_token)=(?P<secret>[^&;\s\"'`#]{1,256})"), Category.PASSWORD),
    TokenRule("connection-string-password", _r(r"(?i)(?:;[ \t]*(?:password|pwd)[ \t]*=[ \t]*(?P<secret>[^;\"'`\n]{1,256})(?=;|[\"'`]|$)|(?:^|[\"'`])[ \t]*(?:password|pwd)[ \t]*=[ \t]*(?P<secret2>[^;\"'`\n]{1,256})(?=;))", re.MULTILINE), Category.DATABASE_CREDENTIAL),
    TokenRule("cli-password-flag", _r(r"(?:^|\s)--password(?:=|\s+)(?P<q>[\"']?)(?P<secret>[^\s\"'`;|&]{1,256})(?P=q)", re.MULTILINE), Category.PASSWORD),
    TokenRule("sql-identified-by", _r(r"(?i)\bIDENTIFIED\s+(?:WITH\s+\w+\s+)?BY\s+(?P<q>['\"])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,256})(?P=q)"), Category.DATABASE_CREDENTIAL),
    TokenRule("sql-password-func", _r(r"(?i)(?<![\w>:.$\\])PASSWORD\s*\(\s*(?P<q>['\"])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,256})(?P=q)\s*\)"), Category.DATABASE_CREDENTIAL),
    TokenRule("sql-set-password", _r(r"(?i)\bSET\s+PASSWORD\s+(?:FOR\s+\S+\s+)?=\s*(?P<q>['\"])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,256})(?P=q)"), Category.DATABASE_CREDENTIAL),
    TokenRule("mysql-p-flag", _r(r"\bmysql\w*\b[^\n]*?\s-p(?P<secret>[^\s\"'`;|&<>]{1,256})"), Category.DATABASE_CREDENTIAL),
    TokenRule("sshpass-flag", _r(r"\bsshpass\s+-p\s*(?P<q>[\"']?)(?P<secret>[^\s\"']{1,256})(?P=q)"), Category.PASSWORD),
    TokenRule("curl-user", _r(r"\bcurl\b[^\n]*?\s(?:-u|--user)[ =]?(?P<q>[\"']?)[^\s:\"']+:(?P<secret>[^\s\"']{1,256})(?P=q)"), Category.PASSWORD),
)

PRIVATE_KEY_BLOCK = _r(
    r"-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----"
    r"(?P<body>(?:(?!-----BEGIN ).){0,20000}?)"
    r"-----END (?P=label)-----",
    re.DOTALL,
)
PRIVATE_KEY_HEADER = _r(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
PUTTY_KEY = _r(r"PuTTY-User-Key-File-\d+:")

_KEY = r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,80})"
ASSIGN_QUOTED = _r(
    _KEY
    + r"[\"']?\s*(?::=|=>|==?|:)\s*(?:[rRbBuUfF]{0,2})(?P<q>[\"'`])"
    r"(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,2048})(?P=q)"
)
ASSIGN_BARE = _r(
    r"^(?P<prefix>[ \t]*(?:export[ \t]+|set[ \t]+|-[ \t]+|ENV[ \t]+|ARG[ \t]+)?)" + _KEY
    + r"[ \t]*(?::|=)[ \t]*(?P<secret>[^\s\"'`]{1,2048})[ \t]*(?:[ \t][#;].*)?$",
    re.MULTILINE,
)
DOCKER_ENV_SPACE = _r(r"^[ \t]*(?:ENV|ARG)[ \t]+" + _KEY + r"[ \t]+(?P<secret>[^\s=][^\s]{0,2047})[ \t]*$", re.MULTILINE)
HEREDOC_ASSIGN = _r(_KEY + r"[\"']?\s*(?::=|=|:)\s*<<[-~]?\s*[\"']?(?P<tag>[A-Za-z_]\w*)[\"']?[ \t]*\n(?P<secret>(?:(?!\n[ \t]*(?P=tag)\b).){1,4096}?)\n[ \t]*(?P=tag)\b", re.DOTALL)
CALL_KEY_VALUE = _r(r"\b(?:define|put|set|setProperty|setdefault|add|header|set_header|with|append|insert)\s*\(\s*(?P<kq>[\"'])(?P<key>[^\"'\n]{1,80})(?P=kq)\s*,\s*(?P<q>[\"'`])(?P<secret>[^\"'`\n]{1,2048})(?P=q)")
SETTER_CALL = _r(r"(?i)\bset_?(?P<key>password|passwd|secret|token|api_?key|credentials?|private_?key|client_?secret)\s*\(\s*(?P<q>[\"'`])(?P<secret>[^\"'`\n]{1,2048})(?P=q)")
AUTH_PAIR = _r(r"(?i)\b(?:HTTPBasicAuth|HTTPDigestAuth|BasicAuth|DigestAuth|basic_auth|auth|creds?|credentials|login)\s*(?:=\s*\(?|\(|:\s*\[|=\s*\[|[\"']\s*=>\s*(?:\[|array\s*\())\s*(?P<q1>[\"'])[^\"'\n]{0,128}(?P=q1)\s*,\s*(?P<q>[\"'])(?P<secret>[^\"'\n]{1,2048})(?P=q)")
WRAPPED_ASSIGN = _r(_KEY + r"[\"']?\s*(?::=|=|:)\s*(?:new\s+String|String|\[\]byte|bytes?|b|str|Buffer\.from|SecretStr|Secret|Password|Some|Optional\.of)\s*\(\s*(?P<q>[\"'`])(?P<secret>[^\"'`\n]{1,2048})(?P=q)")
ENV_DEFAULT = _r(r"(?:(?<![\w$>.])env|getenv|environ\.get|ENV\.fetch|env\.get|os\.Getenv(?:OrDefault)?|config\.get|getProperty)\s*\(\s*(?P<kq>[\"'])(?P<key>[^\"'\n]{1,80})(?P=kq)\s*,\s*(?P<q>[\"'`])(?P<secret>[^\"'`\n]{1,2048})(?P=q)")
INDEX_ASSIGN = _r(r"\[\s*(?P<kq>[\"'])(?P<key>[A-Za-z_][\w.\-]{0,80})(?P=kq)\s*\]\s*=(?![=>])\s*(?P<q>[\"'`])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,2048})(?P=q)")
COMMENT_SECRET = _r(r"(?im)^[ \t]*(?:#|//|--|;|\*|/\*|<!--|REM\b)[^\n]*?\b(?P<key>password|passwd|pwd|passphrase|secret|token|api[ _-]?key)\b[ \t]*(?:is|was|=|:|->)?[ \t]*(?P<q>[\"'`]?)(?P<secret>[^\s\"'`]{6,256})(?P=q)")

# Email addresses. The local part must not follow characters that make it a
# URL userinfo/path, scoped package or decorator; the domain must end in an
# alphabetic TLD and must not continue as an SSH remote path (git@host:repo).
EMAIL = _r(
    r"(?:(?<=mailto:)|(?<![A-Za-z0-9._%+\-/:@\\]))(?P<secret>[A-Za-z0-9_%+\-](?:[A-Za-z0-9._%+\-]{0,63})"
    r"@(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}))"
    r"(?![A-Za-z0-9\-@]|\.[A-Za-z0-9]|:[\w/~])"
)
# RFC 2606 / RFC 6761 documentation and special-use names.
_EMAIL_RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
# SSH algorithm names (chacha20-poly1305@openssh.com) are protocol identifiers.
_EMAIL_PROTOCOL_DOMAINS = ("openssh.com", "libssh.org")
_EMAIL_RESERVED_TLDS = ("example", "test", "invalid", "localhost")
# "logo@2x.png": an asset name, not a domain.
_EMAIL_FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "js", "mjs", "map", "json", "lock", "txt", "md"}

XML_ELEMENT = _r(r"<(?P<key>[A-Za-z_][\w.\-]{0,80})>(?P<secret>[^<>\n]{1,2048})</(?P=key)>")
YAML_BLOCK = _r(r"^(?P<indent>[ \t]*)(?P<key>[A-Za-z_][\w.\-]{0,80}):[ \t]*[|>][-+0-9]*[ \t]*$", re.MULTILINE)

NON_SECRET_VALUES = {
    "none", "null", "nil", "true", "false", "yes", "no", "on", "off", "undefined", "empty",
    "required", "optional", "string", "str", "int", "password", "secret", "token", "bearer",
    "basic", "hidden", "text", "redacted", "example", "changeit_in_prod", "your_password",
    "your-password", "yourpassword", "your_api_key", "your-api-key", "placeholder", "dummy",
    "notset", "not_set", "todo", "tbd", "xxx", "***", "default", "env", "secret_key",
    "api_key", "apikey", "access_token", "username", "user", "admin_username",
}

_REFERENCE_PATTERNS = (
    _r(r"^\$\{[^}]*\}$"),            # ${VAR}
    _r(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),  # $VAR
    _r(r"^%\([^)]+\)s$"),            # %(var)s
    _r(r"^\{\{.*\}\}$"),             # {{ template }}
    _r(r"^<[^<>]+>$"),               # <placeholder>
    _r(r"^%[A-Za-z_]+%$"),           # %VAR%
    _r(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$"),  # {var}
)


_CONTEXT_TOKEN_RULES = {
    "url-credentials", "query-password", "connection-string-password", "cli-password-flag",
    "mysql-p-flag", "sshpass-flag", "curl-user", "sql-identified-by", "sql-password-func", "sql-set-password",
}


def _trivial_value(v: str) -> bool:
    """Values in contextual rules that are references/placeholders, not secrets."""
    v = v.strip()
    if not v or is_placeholder_value(v) or "AI_SAFE_SECRET_" in v:
        return True
    if v[0] in "$%{<" or v.lower() in NON_SECRET_VALUES:
        return True
    return len(set(v)) == 1


def _credential_like(v: str) -> bool:
    """Free-text (comments) values: require a password-like shape."""
    if len(v) < 6 or v.lower() in NON_SECRET_VALUES or _trivial_value(v):
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 2 and bool(re.search(r"[\dA-Z]", v)) and shannon_entropy(v) >= 2.5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_secret_value(value: str, key: str | None, kind: str, quoted: bool) -> bool:
    v = value.strip()
    if len(v) < 4:
        return False
    if is_placeholder_value(v) or PLACEHOLDER_NAME_RE.search(v):
        return False
    low = v.lower()
    if low in NON_SECRET_VALUES:
        return False
    if any(p.match(v) for p in _REFERENCE_PATTERNS):
        return False
    if "${" in v or "{{" in v or "$(" in v:
        # A value is a reference only if little remains once complete
        # reference expressions are removed; "Zz$(abc..." is a literal.
        rest = re.sub(r"\$\{[^}]*\}|\{\{.*?\}\}|\$\([^)]*\)", "", v)
        if rest != v and not re.search(r"[A-Za-z0-9]{4,}", rest):
            return False
    if len(set(v)) == 1:  # "****", "xxxx"
        return False
    if re.fullmatch(r"(?i)(x+|\*+|\.+|-+|_+|#+|0+)", v):
        return False
    if low.startswith(("http://", "https://", "file://", "/", "./", "../", "~/")) and "@" not in v:
        return False
    if re.search(r"(?i)\b(os\.environ|os\.getenv|getenv|process\.env|env\(|System\.getenv|ENV\[)", v):
        return False
    if not quoted:
        # Unquoted values only count in config-like files; in source code an
        # unquoted value is an identifier or expression.
        if kind == "source":
            return False
        if "(" in v or v.endswith(")"):
            return False
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*", v) and kind != "config":
            return False
    # Prose ("Enter your password") is not a credential.
    if re.search(r"\s", v):
        if len(v.split()) > 3 or not is_password_key(key):
            return False
    if not is_password_key(key):
        # token / api key / generic secret names: require some randomness
        if shannon_entropy(v) < 2.5 or len(v) < 8:
            return False
    return True


class BuiltinDetector:
    def __init__(self, custom_rules: Iterable[CustomRule] = (), enable_builtin: bool = True, emails: bool = True) -> None:
        self.enable_builtin = enable_builtin
        self.emails = emails
        self.custom: list[tuple[CustomRule, re.Pattern[str]]] = [
            (r, re.compile(r.regex, re.MULTILINE)) for r in custom_rules
        ]

    # -- public -----------------------------------------------------------

    def scan_text(self, text: str, path: str = "") -> list[RawMatch]:
        kind = file_kind(path)
        lines = _LineIndex(text)
        out: list[RawMatch] = []
        if self.enable_builtin:
            out.extend(self._private_keys(text, lines, path))
            out.extend(self._tokens(text, lines, path))
            out.extend(self._assignments(text, lines, path, kind))
            out.extend(self._yaml_blocks(text, lines, path, kind))
            out.extend(self._context(text, lines, path, kind))
        if self.emails and path != "<commit-message>":
            # Commit messages never reach the workspace; their trailers
            # (Co-Authored-By, Signed-off-by) would only add noise.
            out.extend(self._emails(text, lines))
        out.extend(self._custom(text, lines))
        return _dedupe(out)

    # -- rules ------------------------------------------------------------

    def _private_keys(self, text: str, lines: "_LineIndex", path: str) -> list[RawMatch]:
        out = []
        covered: list[tuple[int, int]] = []
        for m in PRIVATE_KEY_BLOCK.finditer(text):
            secret = m.group(0)
            cat = categorize("private-key", None, secret, path)
            out.append(self._mk("private-key", cat, m.start(), m.end(), lines, secret))
            covered.append((m.start(), m.end()))
        for m in PRIVATE_KEY_HEADER.finditer(text):
            if any(s <= m.start() < e for s, e in covered):
                continue
            # Header without a matching footer: cannot bound the key precisely.
            out.append(self._mk("private-key-unterminated", Category.PRIVATE_KEY, m.start(), m.end(), lines, m.group(0), exact=False))
        for m in PUTTY_KEY.finditer(text):
            out.append(self._mk("putty-private-key", Category.SSH_KEY, m.start(), m.end(), lines, m.group(0), exact=False))
        return out

    def _tokens(self, text: str, lines: "_LineIndex", path: str) -> list[RawMatch]:
        out = []
        for rule in TOKEN_RULES:
            for m in rule.regex.finditer(text):
                group = rule.group
                if "secret2" in rule.regex.groupindex and m.group("secret") is None:
                    group = "secret2"
                secret = m.group(group)
                if not secret or is_placeholder_value(secret) or "${" in secret:
                    continue
                if rule.id in _CONTEXT_TOKEN_RULES and _trivial_value(secret):
                    continue
                if rule.id == "url-username-token" and not (
                    re.search(r"\d", secret) and re.search(r"[A-Za-z]", secret) and shannon_entropy(secret) >= 3.2
                ):
                    continue
                if rule.id == "basic-auth-header" and shannon_entropy(secret) < 3.0:
                    continue
                if rule.id == "bearer-token" and shannon_entropy(secret) < 3.0:
                    continue
                s, e = m.span(group)
                out.append(self._mk(rule.id, rule.category, s, e, lines, secret))
        return out

    def _assignments(self, text: str, lines: "_LineIndex", path: str, kind: str) -> list[RawMatch]:
        out = []
        for m in ASSIGN_QUOTED.finditer(text):
            key = m.group("key")
            if not is_sensitive_key(key):
                continue
            # skip comparisons like `if password == "x"` only when the key is a
            # plain identifier compared in code (still a hardcoded credential:
            # keep it - comparisons against literals are a classic leak)
            raw = m.group("secret")
            if not looks_like_secret_value(raw, key, kind, quoted=True):
                continue
            s, e = m.span("secret")
            cat = categorize("generic-assignment", key, raw, path)
            out.append(self._mk("generic-assignment", cat, s, e, lines, raw, key=key))
        if kind in ("config", "shell"):
            for m in ASSIGN_BARE.finditer(text):
                key = m.group("key")
                if not is_sensitive_key(key):
                    continue
                raw = m.group("secret")
                s, e = m.span("secret")
                # YAML/JSON flow syntax: drop unbalanced trailing , ] }
                while raw and raw[-1] in ",]}" and (raw[-1] == "," or raw.count({"]": "[", "}": "{"}[raw[-1]]) < raw.count(raw[-1])):
                    raw, e = raw[:-1], e - 1
                if raw in ("|", ">", "|-", ">-", "|+", ">+", ""):
                    continue
                if not looks_like_secret_value(raw, key, kind, quoted=False):
                    continue
                cat = categorize("generic-assignment", key, raw, path)
                out.append(self._mk("generic-assignment", cat, s, e, lines, raw, key=key))
            for m in XML_ELEMENT.finditer(text):
                key = m.group("key")
                if not is_sensitive_key(key):
                    continue
                raw = m.group("secret")
                if not looks_like_secret_value(raw, key, "config", quoted=True):
                    continue
                s, e = m.span("secret")
                out.append(self._mk("generic-assignment", categorize("xml", key, raw, path), s, e, lines, raw, key=key))
        return out

    def _context(self, text: str, lines: "_LineIndex", path: str, kind: str) -> list[RawMatch]:
        """Credentials passed positionally / in calls / in heredocs / comments."""
        out = []

        def add(rule_id, m, key, check):
            raw = m.group("secret")
            if not check(raw):
                return
            s_, e_ = m.span("secret")
            out.append(self._mk(rule_id, categorize(rule_id, key, raw, path), s_, e_, lines, raw, key=key if key and key.isidentifier() else None))

        if kind == "config":
            for m in DOCKER_ENV_SPACE.finditer(text):
                if is_sensitive_key(m.group("key")):
                    add("dockerfile-env", m, m.group("key"), lambda v, k=m.group("key"): looks_like_secret_value(v, k, "config", quoted=False))
        for m in HEREDOC_ASSIGN.finditer(text):
            if is_sensitive_key(m.group("key")):
                add("heredoc-secret", m, m.group("key"), lambda v: bool(v.strip()) and not is_placeholder_value(v.strip()))
        for m in CALL_KEY_VALUE.finditer(text):
            k = m.group("key")
            if is_sensitive_key(k):
                add("call-key-value", m, k, lambda v, k=k: looks_like_secret_value(v, k, kind, quoted=True))
        for m in WRAPPED_ASSIGN.finditer(text):
            k = m.group("key")
            if is_sensitive_key(k):
                add("wrapped-assignment", m, k, lambda v, k=k: looks_like_secret_value(v, k, kind, quoted=True))
        for m in ENV_DEFAULT.finditer(text):
            k = m.group("key")
            add("env-default", m, k, lambda v, k=k: (is_sensitive_key(k) and looks_like_secret_value(v, k, kind, quoted=True))
                or (len(v) >= 16 and shannon_entropy(v) >= 3.5 and not _trivial_value(v)))
        for m in SETTER_CALL.finditer(text):
            k = m.group("key")
            add("setter-call", m, k, lambda v, k=k: looks_like_secret_value(v, k, kind, quoted=True))
        for m in AUTH_PAIR.finditer(text):
            add("auth-pair", m, "password", lambda v: looks_like_secret_value(v, "password", kind, quoted=True))
        for m in COMMENT_SECRET.finditer(text):
            add("comment-secret", m, m.group("key").replace(" ", "_"), _credential_like)
        for m in INDEX_ASSIGN.finditer(text):
            k = m.group("key")
            if is_sensitive_key(k):
                add("index-assignment", m, k, lambda v, k=k: looks_like_secret_value(v, k, kind, quoted=True))
        if is_php(path):
            for c in find_call_credentials(text):
                out.append(self._mk(c.rule_id, c.category, c.start, c.end, lines, c.secret, key=c.key))
        return out

    def _yaml_blocks(self, text: str, lines: "_LineIndex", path: str, kind: str) -> list[RawMatch]:
        """``password: |`` followed by an indented block: redact the block."""
        if kind != "config":
            return []
        out = []
        for m in YAML_BLOCK.finditer(text):
            key = m.group("key")
            if not is_sensitive_key(key):
                continue
            indent = len(m.group("indent").expandtabs())
            pos = m.end() + 1
            first_start = None
            last_end = None
            while pos < len(text):
                nl = text.find("\n", pos)
                line_end = len(text) if nl == -1 else nl
                line = text[pos:line_end]
                if line.strip() == "":
                    if nl == -1:
                        break
                    pos = nl + 1
                    continue
                lead = len(line) - len(line.lstrip(" \t"))
                if len(line[:lead].expandtabs()) <= indent:
                    break
                if first_start is None:
                    first_start = pos + lead
                last_end = line_end
                if nl == -1:
                    break
                pos = nl + 1
            if first_start is None or last_end is None:
                continue
            secret = text[first_start:last_end]
            if is_placeholder_value(secret.strip()):
                continue
            cat = categorize("yaml-block", key, secret, path)
            out.append(self._mk("yaml-block-secret", cat, first_start, last_end, lines, secret, key=key))
        return out

    def _emails(self, text: str, lines: "_LineIndex") -> list[RawMatch]:
        out = []
        for m in EMAIL.finditer(text):
            domain = m.group("domain").lower()
            labels = domain.split(".")
            if any(domain == d or domain.endswith("." + d) for d in _EMAIL_RESERVED_DOMAINS + _EMAIL_PROTOCOL_DOMAINS):
                continue
            if labels[-1] in _EMAIL_RESERVED_TLDS or labels[-1] in _EMAIL_FILE_TLDS:
                continue
            if re.fullmatch(r"\d+x", labels[0]):
                continue  # logo@2x.whatever
            raw = m.group("secret")
            if "AI_SAFE_SECRET_" in raw:
                continue
            s, e = m.span("secret")
            out.append(self._mk("email-address", Category.EMAIL, s, e, lines, raw))
        return out

    def _custom(self, text: str, lines: "_LineIndex") -> list[RawMatch]:
        out = []
        for rule, rx in self.custom:
            for m in rx.finditer(text):
                try:
                    secret = m.group(rule.secret_group)
                    s, e = m.span(rule.secret_group)
                except IndexError:
                    continue
                if not secret or is_placeholder_value(secret):
                    continue
                out.append(self._mk(rule.id, rule.category, s, e, lines, secret, engine="custom"))
        return out

    @staticmethod
    def _mk(rule_id, category, start, end, lines, secret, key=None, exact=True, engine="builtin") -> RawMatch:
        return RawMatch(
            rule_id=rule_id,
            category=category,
            start=start,
            end=end,
            line=lines.line_of(start),
            end_line=lines.line_of(max(start, end - 1)),
            key=key,
            exact=exact,
            engine=engine,
            secret=secret,
        )


class _LineIndex:
    def __init__(self, text: str) -> None:
        self.starts = [0]
        self.starts.extend(m.end() for m in re.finditer("\n", text))

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def line_start(self, line: int) -> int:
        return self.starts[line - 1]


def _dedupe(matches: list[RawMatch]) -> list[RawMatch]:
    """Drop matches fully contained in a larger match of the same span start
    region; keep inexact matches always."""
    matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
    out: list[RawMatch] = []
    for m in matches:
        if m.exact and any(o.exact and o.start <= m.start and m.end <= o.end for o in out):
            continue
        out.append(m)
    return out


def key_before(line_text: str, col: int) -> str | None:
    """Best-effort extraction of the assignment key preceding column ``col``."""
    prefix = line_text[:col]
    tail = re.split(r"[\s\"'`(,]", prefix)[-1]
    if "://" in tail or "@" in tail:
        return None  # inside a URL: the "key" would be a username/host, possibly itself a secret
    m = re.search(r"([A-Za-z_][A-Za-z0-9_.\-]{0,80})[\"']?\s*(?::=|=>|=|:)\s*[\"'`]?\s*$", prefix)
    if m and is_plausible_key(m.group(1)):
        return m.group(1)
    m = re.search(r"<([A-Za-z_][\w.\-]{0,80})>\s*$", prefix)
    if m and is_plausible_key(m.group(1)):
        return m.group(1)
    return None


_KEY_SHAPE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]{0,47}")


def is_plausible_key(key: str | None) -> bool:
    """A key name that is safe to turn into a placeholder name: identifier
    shaped, short, and not random-looking (a random "key" may be a secret,
    e.g. a token used as a URL username)."""
    if not key or not _KEY_SHAPE.fullmatch(key):
        return False
    for w in re.split(r"[^A-Za-z0-9]+", key):
        if len(w) >= 20:
            return False
        if len(w) >= 10 and re.search(r"\d", w) and re.search(r"[A-Za-z]", w):
            return False
        if len(w) >= 12 and shannon_entropy(w) > 3.3:
            return False
    return True


__all__ = ["BuiltinDetector", "RawMatch", "key_before", "shannon_entropy", "looks_like_secret_value", "key_words"]
