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

from ai_safe.classifier import (
    categorize, file_kind, is_password_key, is_sensitive_key, is_user_key, is_weak_key,
    key_group, key_words,
)
from ai_safe.config import CustomRule, IdentifierConfig, UsernameConfig
from ai_safe.models import Category
from ai_safe.php_calls import _DEFAULT_USERS, _HOST_RE, _IP_RE, find_call_credentials, is_php
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
    # The password may contain '@' (drivers split userinfo at the *last* '@' before the host).
    TokenRule("url-credentials", _r(
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@'\"`]{0,128}:"
        r"(?P<secret>[^\s'\"`/]{1,256}?)"
        r"@(?=[A-Za-z0-9\[][A-Za-z0-9\[\]._\-%:]*(?:[/?#'\"`\s,;)]|$))"
        r"(?![^\s'\"`/?#]*@)"
    ), Category.DATABASE_CREDENTIAL),
    # Password hashes can be cracked offline: replaced whole.
    TokenRule("password-hash", _r(
        r"(?P<secret>\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}"
        r"|\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"
        r"|\$[56]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86})(?![./A-Za-z0-9])"
    ), Category.PASSWORD),
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
    # libpq conninfo (``host=... password=...``), in any language and any variable
    TokenRule("libpq-password", _r(r"(?i)\b(?:host|hostaddr|dbname|user)\s*=[^\"'\n]*?\bpassword\s*=\s*(?:'(?P<secret>[^'\n]{1,256})'|(?P<secret2>[^\s'\"]{1,256}))"), Category.DATABASE_CREDENTIAL),
    # Webhook URLs carry their token in the path
    TokenRule("discord-webhook", _r(r"(?P<secret>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_\-]{20,})"), Category.ACCESS_TOKEN),
    TokenRule("teams-webhook", _r(r"(?P<secret>https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/[^\s'\"`]{20,})"), Category.ACCESS_TOKEN),
    TokenRule("generic-webhook", _r(r"(?P<secret>https://[^\s'\"`/]+/(?:[^\s'\"`]*/)?(?:webhooks?|hooks)/[^\s'\"`]*[A-Za-z0-9_\-]{24,}[^\s'\"`]*)"), Category.ACCESS_TOKEN),
    # Provider formats anchored by a distinctive prefix
    TokenRule("stripe-webhook-secret", _r(r"\b(?P<secret>whsec_[A-Za-z0-9]{24,})\b"), Category.API_KEY),
    TokenRule("square-access-token", _r(r"\b(?P<secret>sq0atp-[\w\-]{22,}|sq0csp-[\w\-]{40,})"), Category.ACCESS_TOKEN),
    TokenRule("square-oauth-token", _r(r"(?<![A-Za-z0-9+/=])(?P<secret>EAAA[\w\-]{60,})"), Category.ACCESS_TOKEN),
    TokenRule("hubspot-private-app", _r(r"\b(?P<secret>pat-(?:na|eu)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"), Category.ACCESS_TOKEN),
    TokenRule("mailchimp-api-key", _r(r"\b(?P<secret>[0-9a-f]{32}-us\d{1,2})\b"), Category.API_KEY),
    TokenRule("facebook-access-token", _r(r"(?<![A-Za-z0-9+/=])(?P<secret>EAA[A-Za-z0-9]{20,})"), Category.ACCESS_TOKEN),
    TokenRule("google-oauth-client-secret", _r(r"\b(?P<secret>GOCSPX-[A-Za-z0-9_\-]{28})"), Category.API_KEY),
    TokenRule("firebase-fcm-server-key", _r(r"\b(?P<secret>AAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{100,})"), Category.API_KEY),
    TokenRule("telegram-bot-token", _r(r"(?:(?<=['\"])|(?<=bot))(?P<secret>\d{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])"), Category.ACCESS_TOKEN),
    TokenRule("digitalocean-token", _r(r"\b(?P<secret>do[opr]_v1_[0-9a-f]{64})\b"), Category.CLOUD_CREDENTIAL),
    TokenRule("azure-ad-client-secret", _r(r"(?<![A-Za-z0-9_~.\-])(?P<secret>[A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34})(?![A-Za-z0-9_~.\-])"), Category.CLOUD_CREDENTIAL),
    TokenRule("planetscale-token", _r(r"\b(?P<secret>pscale_(?:pw|tkn|oauth)_[A-Za-z0-9_\-.]{32,})"), Category.DATABASE_CREDENTIAL),
    TokenRule("supabase-management-token", _r(r"\b(?P<secret>sbp_[0-9a-f]{40})\b"), Category.ACCESS_TOKEN),
    TokenRule("shopify-token", _r(r"\b(?P<secret>shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32})\b"), Category.ACCESS_TOKEN),
    TokenRule("vault-token", _r(r"\b(?P<secret>hv[sb]\.[A-Za-z0-9_\-]{24,})"), Category.ACCESS_TOKEN),
    TokenRule("doppler-token", _r(r"\b(?P<secret>dp\.(?:st|pt|ct|sa|scim|audit)\.[A-Za-z0-9_\-]{40,})"), Category.ACCESS_TOKEN),
    TokenRule("atlassian-api-token", _r(r"\b(?P<secret>ATATT3[A-Za-z0-9_\-=]{150,})"), Category.ACCESS_TOKEN),
    TokenRule("bitbucket-app-password", _r(r"\b(?P<secret>ATBB[A-Za-z0-9]{28,})\b"), Category.ACCESS_TOKEN),
    TokenRule("postman-api-key", _r(r"\b(?P<secret>PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b"), Category.API_KEY),
    TokenRule("newrelic-key", _r(r"\b(?P<secret>NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9_\-]{32}|[0-9a-fA-F]{36}NRAL)\b"), Category.API_KEY),
    TokenRule("sentry-auth-token", _r(r"\b(?P<secret>sntry[su]_[A-Za-z0-9+/=_\-]{40,})"), Category.ACCESS_TOKEN),
    TokenRule("sentry-dsn", _r(r"https://(?P<secret>[0-9a-f]{32})@[^/\s'\"`]+/\d+"), Category.ACCESS_TOKEN),
    TokenRule("age-secret-key", _r(r"\b(?P<secret>AGE-SECRET-KEY-1[0-9A-Z]{58})\b"), Category.PRIVATE_KEY),
    TokenRule("gcp-api-key-lenient", _r(r"\b(?P<secret>AIza[0-9A-Za-z_\-]{30,45})(?![0-9A-Za-z_\-])"), Category.CLOUD_CREDENTIAL),
    # Any distinctive provider prefix with a random-looking tail (also the verify prefix sweep)
    TokenRule("provider-prefix", _r(
        r"(?<![A-Za-z0-9_\-])(?P<secret>(?:AIza|sq0atp-|sq0csp-|xox[abeoprs]-|gh[pousr]_|github_pat_|gl(?:pat|dt|ptt|rt)-"
        r"|(?:sk|rk)_(?:live|test)_|whsec_|sk-ant-|sk-proj-|GOCSPX-|do[opr]_v1_|pscale_(?:pw|tkn|oauth)_|sbp_"
        r"|shp(?:at|ss|ca|pa)_|hv[sb]\.|PMAK-|NRAK-|sntry[su]_|AGE-SECRET-KEY-1|ATATT3|pypi-AgEI|SG\.)"
        r"(?=[A-Za-z0-9_\-.]*\d)[A-Za-z0-9_\-.]{8,})"
    ), Category.API_KEY),
)

# Public or semi-public identifiers (IDENTIFIER tier, sanitization.identifiers)
IDENTIFIER_RULES: tuple[TokenRule, ...] = (
    TokenRule("stripe-publishable-key", _r(r"\b(?P<secret>pk_(?:live|test)_[A-Za-z0-9]{16,})\b"), Category.IDENTIFIER),
    TokenRule("square-application-id", _r(r"\b(?P<secret>sq0idp-[\w\-]{20,})"), Category.IDENTIFIER),
    TokenRule("twilio-sid", _r(r"\b(?P<secret>(?:AC|MG)[0-9a-f]{32})\b"), Category.IDENTIFIER),
    TokenRule("aws-account-in-arn", _r(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:(?P<secret>\d{12}):"), Category.IDENTIFIER),
    TokenRule("phone-number", _r(r"(?<=['\"])(?P<secret>\+\d{8,15})(?=['\"])"), Category.IDENTIFIER),
)

# Distinctive provider prefixes (and suffixes): under a sensitive key such a
# value is a credential reference even when truncated or low-entropy.
PROVIDER_PREFIX = re.compile(
    r"^(?:AIza|SG\.|sq0atp-|sq0csp-|EAA|IGQV|eyJ|xox[abeoprs]-|gh[pousr]_|github_pat_|gl(?:pat|dt|ptt|rt)-"
    r"|(?:sk|rk)_(?:live|test)_|whsec_|sk-|pat-(?:na|eu)\d-|GOCSPX-|AKIA|ASIA|do[opr]_v1_|pscale_|sbp_"
    r"|shp(?:at|ss|ca|pa)_|hv[sb]\.|dp\.(?:st|pt|ct|sa|scim|audit)\.|PMAK-|NRAK-|NRII-|sntry[su]_"
    r"|AGE-SECRET-KEY-|ATATT3|ATBB|npm_|pypi-|key-)"
    r"|-us\d{1,2}$|NRAL$"
)


def has_provider_prefix(value: str) -> bool:
    v = value.strip()
    return bool(PROVIDER_PREFIX.search(v)) and len(v) >= 8

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
# Trailing closing punctuation (``(password: x)``, ``x.``) stays in the text.
COMMENT_SECRET = _r(r"(?im)^[ \t]*(?:#|//|--|;|\*|/\*|<!--|REM\b)[^\n]*?\b(?P<key>password|passwd|pwd|passphrase|secret|token|api[ _-]?key)\b[ \t]*(?:is|was|=|:|->)?[ \t]*(?P<q>[\"'`]?)(?P<secret>[^\s\"'`]{6,256}?)(?P=q)(?=[)\]},;.]*(?:\s|$))")

# Environment fallbacks: ``getenv('X') ?: 'v'``, ``$_SERVER['X'] ?? 'v'``,
# ``process.env.X || 'v'``, ``os.environ.get('X') or 'v'``, ``${X:-v}``.
ENV_FALLBACK_OP = _r(
    r"(?<![A-Za-z0-9_])(?:getenv|env|apache_getenv|\$_(?:SERVER|ENV)|os\.environ\.get|os\.getenv|process\.env)"
    r"\s*(?:\(\s*|\[\s*|\.)(?P<kq>[\"']?)(?P<key>[A-Za-z_][\w.\-]{0,80})(?P=kq)\s*[\])]?"
    r"\s*(?:\?:|\?\?|\|\||\bor\b)\s*"
    r"(?P<q>[\"'`])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,2048})(?P=q)"
)
SHELL_DEFAULT = _r(r"\$\{(?P<key>[A-Za-z_]\w*):?[-=](?P<secret>[^}\s]{1,2048})\}")

# Containers whose name is sensitive: their string leaves are candidates.
CONTAINER_START = _r(r"(?P<name>\$?[A-Za-z_]\w*|(?P<nq>['\"])[A-Za-z_][\w.\-]*(?P=nq))\s*(?:=|=>|:)\s*(?:array\s*\(|\[|\{)")
FUNCTION_DEF = _r(r"\bfunction\s+&?\s*(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{")
RETURN_ARRAY = _r(r"\breturn\s+(?:array\s*\(|\[|\{)")
LEAF_LITERAL = _r(
    r"(?:(?P<kq>['\"])(?P<leafkey>[^'\"\n]{1,80})(?P=kq)\s*(?:=>|:)\s*)?"
    r"(?P<q>['\"])(?P<secret>(?:\\.|(?!(?P=q))[^\\\n]){1,2048})(?P=q)(?!\s*(?:=>|:))"
)
YAML_PARENT = _r(r"^(?P<indent>[ \t]*)(?P<key>[A-Za-z_][\w.\-]{0,80}):[ \t]*(?:#.*)?$", re.MULTILINE)
YAML_CHILD = _r(r"^(?P<indent>[ \t]+)(?P<key>[A-Za-z_][\w.\-]{0,80}):[ \t]+(?P<secret>[^\n#]+?)[ \t]*$", re.MULTILINE)
_CONTAINER_WORDS = {"keys", "secrets", "credentials", "creds", "tokens", "passwords", "passwds", "apikeys"}
_CONTAINER_FUNC_WORDS = {"key", "keys", "secret", "secrets", "credential", "credentials", "token", "tokens",
                         "password", "passwords"}
_NOT_SECRET_LEAF_WORDS = {"host", "hostname", "server", "url", "uri", "endpoint", "region", "port", "name", "driver",
                          "database", "db", "scheme", "path", "timeout", "version", "type", "mode", "env",
                          "environment", "label", "description", "title", "id", "email", "domain", "bucket"}
_SIBLING_SECRET_CATEGORIES = frozenset({
    Category.PASSWORD, Category.DATABASE_CREDENTIAL, Category.ACCESS_TOKEN, Category.API_KEY,
    Category.GENERIC_SECRET, Category.CLOUD_CREDENTIAL, Category.JWT_SECRET,
})


def is_container_name(name: str, function: bool = False) -> bool:
    words = key_words(name)
    if not words:
        return False
    if function:
        return words[0] == "get" and words[-1] in _CONTAINER_FUNC_WORDS
    return words[-1] in _CONTAINER_WORDS or (is_sensitive_key(name) and not is_weak_key(name))


def _match_bracket(text: str, open_idx: int, limit: int = 20000) -> int | None:
    """Index of the bracket closing ``text[open_idx]`` (quotes respected)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    if open_idx >= len(text) or text[open_idx] not in pairs:
        return None
    stack = [pairs[text[open_idx]]]
    i, n = open_idx + 1, min(len(text), open_idx + limit)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if c != stack.pop():
                return None
            if not stack:
                return i
        i += 1
    return None


def _not_secret_leaf(leaf_key: str) -> bool:
    return bool(set(key_words(leaf_key)) & _NOT_SECRET_LEAF_WORDS) or is_user_key(leaf_key)


def _hostish_value(v: str) -> bool:
    v = v.strip()
    return bool(_IP_RE.match(v) or _HOST_RE.match(v)) or "://" in v or v.startswith(("/", "./", "~/")) or "@" in v


def identifier_value(raw: str, kind: str, quoted: bool) -> bool:
    """A value under an identifier key (``client_id``) that is worth hiding."""
    v = raw.strip()
    if len(v) < 4 or len(v) > 256 or re.search(r"\s", v):
        return False
    if not quoted and kind == "source":
        return False
    if _trivial_value(v) or v.lower() in NON_SECRET_VALUES or any(p.match(v) for p in _REFERENCE_PATTERNS):
        return False
    if is_placeholder_value(v) or "${" in v or "(" in v or "AI_SAFE_" in v:
        return False
    if re.fullmatch(r"(?i)x+|\*+|\.+|-+|_+|#+|0+|your[-_].*|example.*|test|demo|sample|changeme", v):
        return False
    if v.lower().startswith(("http://", "https://", "/", "./")):
        return False
    return not (not quoted and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][\w.]*", v))

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
    "url-credentials", "query-password", "connection-string-password", "cli-password-flag", "libpq-password",
    "mysql-p-flag", "sshpass-flag", "curl-user", "sql-identified-by", "sql-password-func", "sql-set-password",
}


def _trivial_value(v: str) -> bool:
    """Values in contextual rules that are references/placeholders, not secrets."""
    v = v.strip()
    if not v or is_placeholder_value(v) or "AI_SAFE_" in v:
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


_SPDX = re.compile(r"(?i)^(?:[A-Za-z]+-)*(?:A?GPL|LGPL|MIT|BSD|Apache|MPL|ISC|CC|EPL|Unlicense|UNLICENSED|Proprietary|Zlib|Artistic|WTFPL)\b")


def _random_looking(v: str) -> bool:
    """Weak key names (``stripe_key``, ``license``) need a value that looks
    generated: long enough, mixed letters and digits, no spaces, no licence id."""
    if len(v) < 12 or re.search(r"\s", v) or _SPDX.match(v):
        return False
    if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
        return False
    return shannon_entropy(v) >= 3.0


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
    if is_sensitive_key(key) and has_provider_prefix(v):
        return True  # a provider token under a credential key: no entropy / length / prose gates
    if is_weak_key(key) and not _random_looking(v):
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


_REGEX_META = re.compile(r"[\[\](){}|\\^$*+?]")
_REGEX_TOKEN = re.compile(r"\\[dwsDWSbB]|\{\d+(?:,\d*)?\}|\(\?P?<|\(\?:|\[\^?[A-Za-z0-9]-[A-Za-z0-9]")


def looks_like_regex_or_code(value: str) -> bool:
    """A regular expression or code fragment (``(?P<secret>[A-Za-z0-9]{32})``),
    not a credential value."""
    return len(_REGEX_META.findall(value)) >= 2 and bool(_REGEX_TOKEN.search(value))


def accept_engine_finding(rule_id: str, secret: str, key: str | None, path: str) -> bool:
    """Post-filter for findings of another engine (Gitleaks). Provider rules
    are trusted; generic rules must pass the builtin value checks."""
    if looks_like_regex_or_code(secret):
        return False
    if rule_id.lower().startswith("generic"):
        return looks_like_secret_value(secret, key, file_kind(path), quoted=True)
    return True


class BuiltinDetector:
    def __init__(self, custom_rules: Iterable[CustomRule] = (), enable_builtin: bool = True, emails: bool = True,
                 usernames: UsernameConfig | None = None, identifiers: IdentifierConfig | None = None) -> None:
        self.enable_builtin = enable_builtin
        self.emails = emails
        self.usernames = usernames or UsernameConfig()
        self.identifiers = identifiers or IdentifierConfig()
        self._id_keys: list[tuple[str, ...]] | None = None
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
            out.extend(self._containers(text, lines, path, kind))
            if self.usernames.enabled:
                out.extend(self._sibling_users(text, lines, path, kind, out))
        if self.emails and path != "<commit-message>":
            # Commit messages never reach the workspace; their trailers
            # (Co-Authored-By, Signed-off-by) would only add noise.
            out.extend(self._emails(text, lines))
        out.extend(self._custom(text, lines))
        for m in out:
            _strip_format_prefix(m, lines)
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
        rules = TOKEN_RULES + (IDENTIFIER_RULES if self.identifiers.enabled else ())
        for rule in rules:
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
            # comparisons against literals (`if password == "x"`) are a classic leak: kept
            raw = m.group("secret")
            cat = self._kv_category(key, raw, kind, True, path)
            if cat is None:
                continue
            s, e = m.span("secret")
            out.append(self._mk("generic-assignment", cat, s, e, lines, raw, key=key))
        if kind in ("config", "shell"):
            for m in ASSIGN_BARE.finditer(text):
                key = m.group("key")
                if not (is_sensitive_key(key) or self._identifier_key(key)):
                    continue
                raw = m.group("secret")
                s, e = m.span("secret")
                # YAML/JSON flow syntax: drop unbalanced trailing , ] }
                while raw and raw[-1] in ",]}" and (raw[-1] == "," or raw.count({"]": "[", "}": "{"}[raw[-1]]) < raw.count(raw[-1])):
                    raw, e = raw[:-1], e - 1
                if raw in ("|", ">", "|-", ">-", "|+", ">+", ""):
                    continue
                cat = self._kv_category(key, raw, kind, False, path)
                if cat is None:
                    continue
                out.append(self._mk("generic-assignment", cat, s, e, lines, raw, key=key))
            for m in XML_ELEMENT.finditer(text):
                key = m.group("key")
                raw = m.group("secret")
                cat = self._kv_category(key, raw, "config", True, path, rule="xml")
                if cat is None:
                    continue
                s, e = m.span("secret")
                out.append(self._mk("generic-assignment", cat, s, e, lines, raw, key=key))
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
        def add_kv(rule_id, m, k):
            raw = m.group("secret")
            cat = self._kv_category(k, raw, kind, True, path, rule=rule_id)
            if cat is not None:
                s_, e_ = m.span("secret")
                out.append(self._mk(rule_id, cat, s_, e_, lines, raw, key=k if k and k.isidentifier() else None))

        for m in CALL_KEY_VALUE.finditer(text):
            add_kv("call-key-value", m, m.group("key"))
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
            add_kv("index-assignment", m, m.group("key"))
        for rx in (ENV_FALLBACK_OP, SHELL_DEFAULT):
            for m in rx.finditer(text):
                k = m.group("key")
                add("env-fallback", m, k, lambda v, k=k: not _trivial_value(v) and (
                    (is_sensitive_key(k) and looks_like_secret_value(v, k, "config", quoted=True))
                    or (len(v) >= 16 and shannon_entropy(v) >= 3.5)))
        if is_php(path):
            for c in find_call_credentials(text):
                cat = Category.USERNAME if c.role == "user" else c.category
                out.append(self._mk(c.rule_id, cat, c.start, c.end, lines, c.secret, key=c.key))
        return out

    def _identifier_key(self, key: str | None) -> bool:
        if not self.identifiers.enabled or not key:
            return False
        if self._id_keys is None:
            self._id_keys = [tuple(key_words(k)) for k in self.identifiers.keys if key_words(k)]
        words = tuple(key_words(key))
        return any(len(words) >= len(k) and words[-len(k):] == k for k in self._id_keys)

    def _kv_category(self, key: str | None, raw: str, kind: str, quoted: bool, path: str,
                     rule: str = "generic-assignment") -> Category | None:
        """Category of a ``key = value`` pair, or None when it is not sensitive."""
        if is_sensitive_key(key):
            if looks_like_secret_value(raw, key, kind, quoted):
                return categorize(rule, key, raw, path)
            return None
        if self._identifier_key(key) and identifier_value(raw, kind, quoted):
            return Category.IDENTIFIER
        return None

    def _containers(self, text: str, lines: "_LineIndex", path: str, kind: str) -> list[RawMatch]:
        """String leaves of a map / array whose *name* is sensitive
        (``$keys = [...]``, ``function get_api_key() { return [...]; }``,
        ``"secrets": {...}``, YAML ``api_keys:`` blocks). Leaf values must look
        generated (or carry a provider prefix)."""
        out: list[RawMatch] = []
        regions: list[tuple[int, int, str]] = []
        for m in CONTAINER_START.finditer(text):
            name = m.group("name").strip("'\"$")
            if not is_container_name(name):
                continue
            end = _match_bracket(text, m.end() - 1)
            if end is not None:
                regions.append((m.end(), end, name))
        for m in FUNCTION_DEF.finditer(text):
            if not is_container_name(m.group("name"), function=True):
                continue
            body_end = _match_bracket(text, m.end() - 1)
            if body_end is None:
                continue
            for r in RETURN_ARRAY.finditer(text, m.end(), body_end):
                end = _match_bracket(text, r.end() - 1)
                if end is not None:
                    regions.append((r.end(), end, m.group("name")))
        for start, end, name in regions:
            for lm in LEAF_LITERAL.finditer(text, start, end):
                leaf_key = lm.group("leafkey")
                raw = lm.group("secret")
                self._container_leaf(out, lines, path, kind, name, leaf_key, raw, lm.span("secret"))
        if kind == "config":
            for m in YAML_PARENT.finditer(text):
                name = m.group("key")
                if not is_container_name(name):
                    continue
                indent = len(m.group("indent").expandtabs())
                pos = m.end() + 1
                for cm in YAML_CHILD.finditer(text, pos):
                    if cm.start() != pos or len(cm.group("indent").expandtabs()) <= indent:
                        break
                    raw = cm.group("secret").strip().strip("'\"")
                    vs = text.find(raw, cm.start("secret"), cm.end("secret")) if raw else -1
                    if vs >= 0:
                        self._container_leaf(out, lines, path, kind, name, cm.group("key"), raw, (vs, vs + len(raw)))
                    pos = cm.end() + 1
        return out

    def _container_leaf(self, out, lines, path, kind, name, leaf_key, raw, span) -> None:
        if leaf_key and (is_sensitive_key(leaf_key) or self._identifier_key(leaf_key) or _not_secret_leaf(leaf_key)):
            return  # handled by the key rules, or a host / user / url field
        if not looks_like_secret_value(raw, None, kind, quoted=True) and not has_provider_prefix(raw):
            return
        if not (has_provider_prefix(raw) or _random_looking(raw)) or _hostish_value(raw):
            return
        key = f"{name}_{leaf_key}" if leaf_key else name
        cat = categorize("container-leaf", key, raw, path)
        out.append(self._mk("container-leaf", cat, span[0], span[1], lines, raw, key=key if is_plausible_key(key) else None))

    def _sibling_users(self, text: str, lines: "_LineIndex", path: str, kind: str, found: list[RawMatch]) -> list[RawMatch]:
        """A user name next to a detected password / secret / token: in the same
        mapping, the same env / constant group (``DB_USER`` + ``DB_PASS``) or
        adjacent statements."""
        secrets_ = [m for m in found if m.key and m.category in _SIBLING_SECRET_CATEGORIES]
        if not secrets_:
            return []
        text_lines = text.split("\n")

        def indent(line_no: int) -> str:
            t = text_lines[line_no - 1] if 0 < line_no <= len(text_lines) else ""
            return t[: len(t) - len(t.lstrip())]

        groups = {key_group(m.key) for m in secrets_}
        bare: dict[int, set[str]] = {}
        for m in secrets_:
            if not key_group(m.key):
                bare.setdefault(m.line, set()).add(indent(m.line))

        def sibling(grp: tuple[str, ...], line: int, ind: str) -> bool:
            if grp:
                return grp in groups
            if line in bare:
                return True
            return any(ind in bare.get(ln, ()) for ln in range(line - 4, line + 5))

        out: list[RawMatch] = []
        seen: set[tuple[int, int]] = set()
        for rx, quoted in self._user_patterns(kind):
            for m in rx.finditer(text):
                key = m.group("key")
                if not is_user_key(key) or is_sensitive_key(key):
                    continue
                raw = m.group("secret")
                if not self._user_value(raw):
                    continue
                s, e = m.span("secret")
                if (s, e) in seen:
                    continue
                line = lines.line_of(s)
                if not sibling(key_group(key), line, indent(line)):
                    continue
                seen.add((s, e))
                out.append(self._mk("sibling-username", Category.USERNAME, s, e, lines, raw, key=key))
        return out

    @staticmethod
    def _user_patterns(kind: str):
        pats = [(ASSIGN_QUOTED, True), (CALL_KEY_VALUE, True), (INDEX_ASSIGN, True)]
        if kind in ("config", "shell"):
            pats += [(ASSIGN_BARE, False), (DOCKER_ENV_SPACE, False), (XML_ELEMENT, True)]
        return pats

    def _user_value(self, raw: str) -> bool:
        v = raw.strip()
        if not v or len(v) > 128 or re.search(r"\s", v) or _trivial_value(v):
            return False
        if v.lower() in _DEFAULT_USERS and not self.usernames.include_default_usernames:
            return False
        if "@" in v and EMAIL.fullmatch(v):
            return False  # emails have their own rule
        if any(p.match(v) for p in _REFERENCE_PATTERNS) or "(" in v:
            return False
        return not _hostish_value(v)

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
            if PLACEHOLDER_NAME_RE.search(raw):
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


_FORMAT_PREFIX = re.compile(r"(?i)^(?:base64|b64|hex|hex2bin):(?=[A-Za-z0-9+/=_\-]{8,}$)")


def _strip_format_prefix(m: RawMatch, lines: "_LineIndex") -> None:
    """``base64:<key>``: the format prefix stays readable, only the key is secret."""
    if m.engine != "builtin" or not m.exact:
        return
    pm = _FORMAT_PREFIX.match(m.secret)
    if pm:
        m.secret = m.secret[pm.end():]
        m.start += pm.end()
        m.line = lines.line_of(m.start)


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
    max_end = -1  # largest end of an exact match kept so far (all of them start at or before m.start)
    for m in matches:
        if m.exact and m.end <= max_end:
            continue
        out.append(m)
        if m.exact:
            max_end = max(max_end, m.end)
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


__all__ = ["BuiltinDetector", "RawMatch", "accept_engine_finding", "key_before", "shannon_entropy", "looks_like_secret_value", "key_words"]
