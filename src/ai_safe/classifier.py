"""Secret and file classification.

* ``categorize`` maps a detector rule / key name / value to a :class:`Category`.
* ``match_exclude`` decides whether a path is a sensitive file that must never
  be copied into the AI workspace.
* ``file_kind`` drives format-aware detection (config vs. source files).
* ``is_sensitive_key`` decides whether an assignment key names a credential.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath

from ai_safe.models import Category

# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------


def match_exclude(rel: str, patterns: list[str]) -> str | None:
    """Return the first matching pattern, or ``None``.

    Semantics (case-insensitive, to defeat case tricks on macOS/Windows):
    * ``name/``   matches a directory component anywhere in the path
    * ``a/b*``    (contains ``/``) is matched against the full path and its prefixes
    * ``name``    is matched against every path component (file or directory)
    """
    parts = [p.casefold() for p in PurePosixPath(rel).parts]
    full = "/".join(parts)
    for pattern in patterns:
        pat = pattern.casefold()
        if pat.endswith("/"):
            name = pat.rstrip("/")
            if "/" in name:
                if full.startswith(name + "/") or fnmatch.fnmatchcase(full, name + "/*"):
                    return pattern
            elif any(fnmatch.fnmatchcase(p, name) for p in parts[:-1]):
                return pattern
        elif "/" in pat:
            pat = pat.lstrip("/")
            prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
            if any(fnmatch.fnmatchcase(p, pat) for p in prefixes):
                return pattern
        else:
            if any(fnmatch.fnmatchcase(p, pat) for p in parts):
                return pattern
    return None


CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".tf", ".hcl", ".xml", ".plist", ".config", ".cnf",
}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat", ".cmd"}
CONFIG_NAMES = {
    "dockerfile", "makefile", "procfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", ".pgpass", "pip.conf",
}


def file_kind(rel: str) -> str:
    """'config', 'shell' or 'source'."""
    p = PurePosixPath(rel)
    name = p.name.casefold()
    suffix = p.suffix.casefold()
    if suffix in (".example", ".sample", ".template", ".dist", ".tmpl", ".orig", ".bak", ".old"):
        stem = PurePosixPath(p.stem)
        name, suffix = stem.name.casefold(), stem.suffix.casefold()
    if ".env" in name:
        return "config"
    if name in CONFIG_NAMES or name.startswith(".env") or suffix in CONFIG_EXTENSIONS:
        return "config"
    if suffix in SHELL_EXTENSIONS:
        return "shell"
    return "source"


# Changes to these are always blocked during review/integration: they control
# the security tooling itself or the workspace boundary.
SECURITY_TOOL_FILES = (
    "ai-safe.yaml",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".ai-safe-workspace.json",
)

# Changes to these are allowed but flagged for careful human review because
# they can execute code, change the supply chain or exfiltrate data.
SENSITIVE_CONFIG_PATTERNS = (
    ".github/",
    ".gitlab-ci.yml",
    ".circleci/",
    "Jenkinsfile",
    "azure-pipelines.yml",
    ".pre-commit-config.yaml",
    ".husky/",
    ".githooks/",
    ".gitattributes",
    ".gitmodules",
    "Dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "Makefile",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements*.txt",
    "Pipfile",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
    "build.gradle",
    "pom.xml",
    "settings.py",
    "config/",
    "*.tf",
    "*.hcl",
    "k8s/",
    "helm/",
)


def is_security_tool_file(rel: str) -> bool:
    return PurePosixPath(rel).name.casefold() in {f.casefold() for f in SECURITY_TOOL_FILES}


def is_sensitive_config(rel: str) -> bool:
    return match_exclude(rel, list(SENSITIVE_CONFIG_PATTERNS)) is not None


# ---------------------------------------------------------------------------
# Key analysis
# ---------------------------------------------------------------------------

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

SECRET_WORDS = {
    "password", "passwd", "pwd", "pw", "pass", "passphrase", "passcode", "secret", "secrets",
    "token", "apikey", "credential", "credentials", "creds", "privatekey", "pat",
    "connectionstring", "connstr", "dsn", "auth",
}
SECRET_BIGRAMS = {
    ("api", "key"), ("access", "key"), ("auth", "key"), ("private", "key"),
    ("client", "secret"), ("signing", "key"), ("encryption", "key"), ("master", "key"),
    ("session", "key"), ("secret", "key"), ("account", "key"), ("app", "secret"),
    ("api", "secret"), ("consumer", "secret"), ("connection", "string"), ("auth", "token"),
    ("access", "token"), ("refresh", "token"), ("bearer", "token"), ("shared", "key"),
    ("webhook", "secret"), ("license", "key"), ("sas", "token"), ("storage", "key"),
}
# Trailing words that indicate the value is *about* a secret, not the secret.
NON_SECRET_SUFFIXES = {
    "url", "uri", "endpoint", "path", "file", "filename", "dir", "name", "type", "field",
    "label", "prompt", "message", "msg", "hint", "text", "title", "placeholder", "length",
    "len", "min", "max", "size", "count", "expiry", "expires", "expiration", "ttl",
    "timeout", "header", "param", "policy", "format", "pattern", "regex", "rule", "rules",
    "env", "var", "variable", "enabled", "required", "valid", "validator", "validation",
    "reset", "changed", "updated", "created", "at", "prefix", "suffix", "kind", "mode",
    "provider", "algorithm", "algo", "location", "store", "manager", "lifetime", "version",
    "cache", "limit", "id", "ids", "hash", "hashed", "digest", "salt", "rounds", "strength",
}


def key_words(key: str) -> list[str]:
    key = _CAMEL_RE.sub("_", key)
    return [w.lower() for w in _SPLIT_RE.split(key) if w]


def is_sensitive_key(key: str | None) -> bool:
    if not key:
        return False
    words = key_words(key)
    if not words:
        return False
    if words[-1] in NON_SECRET_SUFFIXES and len(words) > 1:
        # "vault_secret_id" style names are still secrets
        if not (words[-1] == "id" and "secret" in words):
            return False
    joined = "".join(words)
    if any(w in SECRET_WORDS for w in words):
        return True
    if any(pair in SECRET_BIGRAMS for pair in zip(words, words[1:])):
        return True
    for compact in ("apikey", "secretkey", "accesskey", "privatekey", "authtoken", "accesstoken", "clientsecret", "dbpass"):
        if compact in joined:
            return True
    return False


def is_password_key(key: str | None) -> bool:
    if not key:
        return False
    words = key_words(key)
    return any(w in {"password", "passwd", "pwd", "pass", "passphrase", "passcode", "secret"} for w in words)


# ---------------------------------------------------------------------------
# Categorisation
# ---------------------------------------------------------------------------

_CLOUD_HINTS = ("aws", "amazon", "gcp", "google", "azure", "alibaba", "digitalocean", "heroku",
                "linode", "cloudflare", "ibm", "oracle-cloud", "scaleway", "vultr", "gcs", "s3")
_DB_HINTS = ("db", "database", "postgres", "postgresql", "pg", "mysql", "mariadb", "mongo",
             "mongodb", "redis", "sql", "mssql", "oracle", "cassandra", "couchdb", "elastic",
             "dsn", "jdbc", "connectionstring", "connstr")
_TOKEN_HINTS = ("token", "github", "gitlab", "slack", "bearer", "pat", "npm", "pypi",
                "discord", "telegram", "twilio-auth", "oauth", "refresh", "session")
_API_HINTS = ("api-key", "apikey", "api_key", "openai", "anthropic", "stripe", "sendgrid",
              "mailgun", "mailchimp", "twilio", "algolia", "api")


def categorize(rule_id: str, key: str | None = None, secret: str = "", file: str = "") -> Category:
    rid = rule_id.lower()
    words = key_words(key) if key else []
    wordset = set(words)
    joined = "".join(words)

    key_is_private_key = "privatekey" in joined or ("private" in wordset and "key" in wordset)
    if "private-key" in rid or "private_key" in rid or "privatekey" in rid or "-----BEGIN" in secret or key_is_private_key:
        if "ssh" in rid or "OPENSSH" in secret or "PuTTY" in secret or PurePosixPath(file).name.startswith(("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")):
            return Category.SSH_KEY
        return Category.PRIVATE_KEY
    if "ssh" in rid:
        return Category.SSH_KEY
    if "jwt" in rid or "jwt" in wordset or "jwt" in joined:
        if rid in ("jwt", "jwt-token") or secret.startswith("eyJ"):
            return Category.ACCESS_TOKEN
        return Category.JWT_SECRET
    if "url-credentials" in rid or "connection-string" in rid:
        return Category.DATABASE_CREDENTIAL
    if any(h in wordset for h in _DB_HINTS) or any(h in joined for h in ("database", "postgres", "mysql", "mongo", "redis", "connectionstring")):
        if any(w in wordset for w in ("password", "passwd", "pwd", "pass", "secret", "credentials", "dsn")) or "connectionstring" in joined or "dsn" in wordset:
            return Category.DATABASE_CREDENTIAL
    if any(h in rid for h in _CLOUD_HINTS) or any(h in wordset for h in ("aws", "gcp", "azure", "google", "s3")):
        return Category.CLOUD_CREDENTIAL
    if any(w in wordset for w in ("password", "passwd", "pwd", "pass", "passphrase", "passcode")):
        return Category.PASSWORD
    if any(h in rid for h in _API_HINTS) or "apikey" in joined or ("api" in wordset and "key" in wordset):
        return Category.API_KEY
    if any(h in rid for h in _TOKEN_HINTS) or "token" in wordset or "token" in joined:
        return Category.ACCESS_TOKEN
    return Category.GENERIC_SECRET
