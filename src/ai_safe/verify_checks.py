"""Verification checks that do not depend on the builtin detector.

``verify`` and the post-redaction re-scan use the same detector as
``sanitize``, so on their own they share its blind spots. These checks look at
the *result* instead:

1. **Placeholder adjacency** - a placeholder glued to three or more token
   characters (``${...}Zz9Yy8``, ``prod_${...}``, ``${...}-server.corp``) means a
   partial replacement or an over-replacement.
2. **URL re-parse** - in a URL with a placeholder in its userinfo, the password
   must be exactly one placeholder directly followed by ``@host``.
3. **Prefix sweep** - distinctive provider prefixes (``ghp_``, ``sk_live_``,
   ``AIza`` ...) are swept without any key, length or entropy gate.
4. **High-entropy literal sweep** - long random-looking string literals are
   reported for human review (WARNING).
5. **Infra sweep** - internal host names (internal pseudo-TLDs, configured
   organisation domains) and private IP addresses left over (WARNING).

Each finding names the file, line and check only - never a value.
"""

from __future__ import annotations

import re
import string
from pathlib import PurePosixPath

from ai_safe.detectors import TOKEN_RULES, shannon_entropy
from ai_safe.infra import PROVIDER_TAIL, leftover_infra
from ai_safe.models import Severity
from ai_safe.security import ANY_PLACEHOLDER_RE, is_placeholder_value

_ADJ = frozenset(string.ascii_letters + string.digits + "+_-.~")
_PREFIX_SWEEP = next(r.regex for r in TOKEN_RULES if r.id == "provider-prefix")
_URL_AUTH = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://(?P<auth>[^\s/'\"`?#]*)@")
_LITERAL = re.compile(r"(?P<q>['\"`])(?P<v>[^'\"`\s\\]{20,512})(?P=q)")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DOTTED = re.compile(r"[A-Za-z_$][\w$]*(?:[.:\\][A-Za-z_$][\w$]*)+")
_NO_ENTROPY_SWEEP = (".lock", ".min.js", ".min.css", ".map", ".svg", ".sum", ".snap")
_NO_ENTROPY_NAMES = {"package-lock.json", "yarn.lock", "composer.lock", "pnpm-lock.yaml", "go.sum", "cargo.lock"}
MAX_ENTROPY_WARNINGS_PER_FILE = 5


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _run_left(text: str, i: int) -> str:
    j = i
    while j > 0 and text[j - 1] in _ADJ:
        j -= 1
    return text[j:i]


def _run_right(text: str, i: int) -> str:
    j = i
    while j < len(text) and text[j] in _ADJ:
        j += 1
    return text[i:j]


def adjacency_issues(text: str, kept_suffixes: tuple[str, ...] = ()) -> list[tuple[int, str]]:
    """(line, message) for placeholders glued to token characters."""
    out = []
    for m in ANY_PLACEHOLDER_RE.finditer(text):
        name = m.group(0)[2:-1]
        left, right = _run_left(text, m.start()), _run_right(text, m.end())
        if left.endswith("bot") and len(left) == 3 and text[m.start() - 4:m.start() - 3] == "/":
            left = ""  # Telegram: .../bot<token>/...
        if name.startswith("AI_SAFE_DOMAIN_") and left.endswith("."):
            left = ""  # scope: domain keeps the subdomain labels
        if name.startswith(("AI_SAFE_HOST_", "AI_SAFE_DOMAIN_")) and right.startswith("."):
            if any(text.startswith(sfx, m.end()) for sfx in kept_suffixes) or PROVIDER_TAIL.match(text, m.end()):
                right = ""  # a kept provider suffix (.rds.amazonaws.com)
        if len(left) >= 3 or len(right) >= 3:
            side = "before" if len(left) >= 3 else "after"
            out.append((_line(text, m.start()),
                        f"placeholder directly adjacent to {max(len(left), len(right))} token characters {side} it "
                        "(partial replacement or over-replacement)"))
    return out


def url_issues(text: str) -> list[tuple[int, str]]:
    """A URL whose userinfo holds a placeholder must hold exactly one placeholder per part."""
    out = []
    for m in _URL_AUTH.finditer(text):
        auth = m.group("auth")
        if "AI_SAFE_" not in auth:
            continue
        user, sep, pw = auth.partition(":")
        bad = (sep and "AI_SAFE_" in pw and not ANY_PLACEHOLDER_RE.fullmatch(pw)) or (
            "AI_SAFE_" in user and not ANY_PLACEHOLDER_RE.fullmatch(user))
        if bad:
            out.append((_line(text, m.start()), "URL userinfo is not exactly one placeholder followed by @host "
                                                "(part of the credential may remain)"))
    return out


def prefix_issues(text: str) -> list[tuple[int, str]]:
    out = []
    for m in _PREFIX_SWEEP.finditer(text):
        if is_placeholder_value(m.group("secret")):
            continue
        out.append((_line(text, m.start()), "distinctive provider token prefix present (prefix sweep)"))
    return out


def entropy_issues(text: str, rel: str) -> list[tuple[int, str]]:
    name = PurePosixPath(rel).name.casefold()
    if name in _NO_ENTROPY_NAMES or name.endswith(_NO_ENTROPY_SWEEP):
        return []
    out = []
    for m in _LITERAL.finditer(text):
        v = m.group("v")
        if "AI_SAFE_" in v or v.startswith(("data:", "sha256-", "sha384-", "sha512-")):
            continue
        if "://" in v or v.startswith(("/", "./", "../")) or v.count("/") >= 2:
            continue
        if re.fullmatch(r"[0-9a-fA-F]+", v) or _UUID.fullmatch(v) or _DOTTED.fullmatch(v):
            continue
        if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)) or shannon_entropy(v) < 3.5:
            continue
        out.append((_line(text, m.start()), "high-entropy string literal (review: possible undetected secret)"))
        if len(out) >= MAX_ENTROPY_WARNINGS_PER_FILE:
            break
    return out


def run_checks(report, text: str, rel: str, kept_suffixes: tuple[str, ...] = (),
               flagged_lines: set[int] | None = None, infra=None) -> None:
    """Add the independent checks' issues for one file to ``report``."""
    flagged = flagged_lines or set()
    for line, msg in adjacency_issues(text, kept_suffixes):
        report.add(Severity.ERROR, "placeholder-adjacent", rel, msg, line)
    for line, msg in url_issues(text):
        report.add(Severity.ERROR, "url-userinfo", rel, msg, line)
    for line, msg in prefix_issues(text):
        if line not in flagged:
            report.add(Severity.ERROR, "prefix-sweep", rel, msg, line)
    for line, msg in entropy_issues(text, rel):
        if line not in flagged:
            report.add(Severity.WARNING, "high-entropy-literal", rel, msg, line)
    if infra is not None and infra.enabled:
        for line in leftover_infra(text, rel, infra, set(infra.org_domains)):
            report.add(Severity.WARNING, "infra-leftover", rel,
                       "internal host name or private IP address left in the workspace (infra sweep)", line)
