"""Shared data types.

Secret values are carried in memory only. Every type that can hold a secret
keeps it out of ``repr`` and out of the public/serialised form.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Category(str, enum.Enum):
    API_KEY = "API_KEY"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    PASSWORD = "PASSWORD"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    PRIVATE_KEY = "PRIVATE_KEY"
    SSH_KEY = "SSH_KEY"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    JWT_SECRET = "JWT_SECRET"
    GENERIC_SECRET = "GENERIC_SECRET"
    EMAIL = "EMAIL"  # personal data, not a credential
    USERNAME = "USERNAME"  # login name next to a credential: not a credential itself
    IDENTIFIER = "IDENTIFIER"  # account / tenant / client IDs: not credentials, but identify the organisation
    # Infrastructure (restorable on integration, never AI_SAFE_SECRET_)
    HOSTNAME = "HOSTNAME"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"


# Categories whose values are not credentials: replaced only where detected
# (never as a substring elsewhere) and not treated as leaked secrets.
NON_PROPAGATING_CATEGORIES = frozenset({Category.USERNAME, Category.EMAIL, Category.IDENTIFIER})
INFRA_CATEGORIES = frozenset({Category.HOSTNAME, Category.DOMAIN, Category.IP_ADDRESS, Category.CLOUD_RESOURCE})


class Location(str, enum.Enum):
    TRACKED = "tracked"
    UNTRACKED = "untracked"
    IGNORED = "ignored"
    STAGED = "staged"
    UNSTAGED = "unstaged"
    HISTORY = "history"
    FILESYSTEM = "filesystem"  # directory that is not a Git repository
    WORKSPACE = "workspace"
    IMPORTED = "imported"  # from an external Gitleaks JSON report


WORKING_TREE_LOCATIONS = frozenset(
    {Location.TRACKED, Location.UNTRACKED, Location.IGNORED, Location.FILESYSTEM}
)


class Severity(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @property
    def blocking(self) -> bool:
        return self in (Severity.ERROR, Severity.CRITICAL)

    @property
    def rank(self) -> int:
        return ["INFO", "WARNING", "ERROR", "CRITICAL"].index(self.value)


@dataclass(eq=False)
class Finding:
    """A detected credential. ``secret`` never leaves the process."""

    rule_id: str
    category: Category
    file: str
    line: int
    end_line: int
    engine: str
    location: Location
    key: str | None = None
    commit: str | None = None
    exact: bool = True
    secret: str = field(default="", repr=False)
    fingerprint: str = ""
    kind: str | None = None  # infrastructure kind (host, domain, ip, net, bucket, account, project)

    def public(self) -> dict[str, Any]:
        """Serialisable view without the secret value."""
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "engine": self.engine,
            "location": self.location.value,
            "key": self.key,
            "commit": self.commit,
            "exact": self.exact,
            "fingerprint": self.fingerprint,
            "kind": self.kind,
        }


INFRA_KIND_CATEGORY = {
    "host": Category.HOSTNAME, "domain": Category.DOMAIN, "ip": Category.IP_ADDRESS, "net": Category.IP_ADDRESS,
    "bucket": Category.CLOUD_RESOURCE, "account": Category.CLOUD_RESOURCE, "project": Category.CLOUD_RESOURCE,
}


@dataclass
class Issue:
    """A verification / review / integration problem. Never contains secrets."""

    severity: Severity
    code: str
    path: str
    message: str
    line: int | None = None

    def public(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


def is_blocking(issues: list[Issue]) -> bool:
    return any(i.severity.blocking for i in issues)
