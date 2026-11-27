"""Redaction engine.

Gitleaks (and the builtin detector) *detect*; this module *redacts*:

1. every finding must be exact (bounded) - otherwise fail closed;
2. the detected occurrence of each secret is located in the file content, and
   the value is *propagated*: replaced wherever else it occurs, but only on
   token boundaries. An occurrence embedded in a larger token (``base64:<x>tail``)
   is strong evidence that the enclosing token is itself a secret: the token is
   registered and replaced as a whole, so no fragment of it leaks. Values that
   are not credentials (usernames, emails, identifiers) are never propagated,
   and low-entropy values propagate only as whole tokens;
3. overlapping spans are merged and replaced by a deterministic placeholder
   ``${AI_SAFE_SECRET_<NAME>}``;
4. the result is re-scanned; any residual secret, or any detected value still
   present, raises :class:`RedactionError` and the caller excludes the file.

Placeholders are derived from the assignment key (``DB_PASSWORD`` ->
``AI_SAFE_SECRET_DB_PASSWORD``) or, without a key, from the category plus a
keyed fingerprint. The same secret always maps to the same placeholder. A value
used under several unrelated keys is named ``AI_SAFE_SECRET_SHARED_<CATEGORY>_<fp>``.
"""

from __future__ import annotations

import re
import secrets as _secrets
import string
from dataclasses import dataclass, field

from ai_safe.classifier import categorize, key_words
from ai_safe.detectors import BuiltinDetector, is_plausible_key, key_before, shannon_entropy
from ai_safe.models import INFRA_CATEGORIES, NON_PROPAGATING_CATEGORIES, Category, Finding
from ai_safe.security import PLACEHOLDER_PREFIX, hmac_fingerprint, is_placeholder_value

GLOBAL_REPLACE_MIN_LEN = 8   # propagate to every file
FILE_REPLACE_MIN_LEN = 6     # propagate within the file where it was found
CHECK_MIN_LEN = 6            # post-redaction "value still present" check
LOW_ENTROPY = 3.0            # below: propagate only as a whole token, never expand
MAX_EXPANDED_LEN = 1024      # an enclosing token longer than this cannot be bounded: fail closed

# Propagation modes (see module docstring)
EXPAND = "expand"  # whole-token occurrences replaced; embedded ones expand to the enclosing token
TOKEN = "token"    # whole-token occurrences replaced; embedded ones left alone
NONE = "none"      # only the detected occurrence is replaced
DNS = "dns"        # infrastructure: whole DNS-label-bounded occurrences only


class RedactionError(Exception):
    """Secret could not be confidently redacted. Message never contains it."""


@dataclass
class PlaceholderEntry:
    name: str
    category: Category
    fingerprint: str
    key: str | None
    files: set[str] = field(default_factory=set)
    occurrences: int = 0
    secret: str = field(default="", repr=False)
    propagate: str = EXPAND
    also_used_as: list[str] = field(default_factory=list)
    kind: str | None = None  # infrastructure kind (host, domain, ip, net, bucket, account, project)
    original: str = field(default="", repr=False)  # infrastructure: first-seen text, restored on integration
    pseudonym: str | None = None  # infrastructure.mode = pseudonym: a valid stand-in instead of ${...}

    @property
    def token(self) -> str:
        return self.pseudonym or "${" + self.name + "}"

    @property
    def restorable(self) -> bool:
        return self.category in INFRA_CATEGORIES


_DROP_WORDS = {"self", "this", "os", "environ", "config", "cfg", "settings", "export"}


def _normalise_key(key: str) -> str:
    words = [w for w in key_words(key) if w not in _DROP_WORDS]
    name = "_".join(w.upper() for w in words)[:60].strip("_")
    return name


def _alnum(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def _overlaps(key: str, secret: str) -> bool:
    k, v = _alnum(key), _alnum(secret)
    return len(v) >= 6 and v in k


def propagation_mode(secret: str, category: Category) -> str:
    if category in INFRA_CATEGORIES:
        return DNS
    if category in NON_PROPAGATING_CATEGORIES:
        return NONE
    if shannon_entropy(secret) < LOW_ENTROPY:
        return TOKEN
    return EXPAND


def identity(secret: str, category: Category) -> str:
    """Registry identity: DNS names are case-insensitive and may end in a dot."""
    if category in (Category.HOSTNAME, Category.DOMAIN):
        return secret.lower().rstrip(".")
    return secret


class PlaceholderRegistry:
    def __init__(self, salt: bytes, deterministic: bool = True) -> None:
        self.salt = salt
        self.deterministic = deterministic
        self.by_secret: dict[str, PlaceholderEntry] = {}
        self.by_name: dict[str, PlaceholderEntry] = {}
        # identity -> location -> keys seen there (for SHARED naming)
        self._uses: dict[str, dict[tuple, set[str]]] = {}
        self._frozen = False

    def get(self, secret: str) -> PlaceholderEntry | None:
        return self.by_secret.get(secret) or self.by_secret.get(secret.lower().rstrip("."))

    def register(self, secret: str, category: Category, key: str | None, *, location: tuple | None = None,
                 prefix: str = PLACEHOLDER_PREFIX, kind: str | None = None) -> PlaceholderEntry:
        ident = identity(secret, category)
        if location is not None and key and is_plausible_key(key) and not _overlaps(key, secret):
            self._uses.setdefault(ident, {}).setdefault(location, set()).add(_normalise_key(key))
        if ident in self.by_secret:
            return self.by_secret[ident]
        fp = hmac_fingerprint(ident, self.salt)
        if key is not None and (not is_plausible_key(key) or _overlaps(key, secret)):
            key = None
        suffix_src = fp if self.deterministic else _secrets.token_hex(12)
        base = _normalise_key(key) if key else ""
        if base:
            name = prefix + base
            if name in self.by_name:
                name = f"{name}_{suffix_src[:6].upper()}"
        elif prefix == PLACEHOLDER_PREFIX:
            name = f"{prefix}{category.value}_{suffix_src[:6].upper()}"
        else:
            name = f"{prefix}{suffix_src[:6].upper()}"
        n = 8
        while name in self.by_name:
            name = f"{prefix}{base or category.value}_{suffix_src[:n].upper()}"
            n += 2
        entry = PlaceholderEntry(name=name, category=category, fingerprint=fp, key=key, secret=ident,
                                 propagate=propagation_mode(ident, category), kind=kind, original=secret)
        self.by_secret[ident] = entry
        self.by_name[name] = entry
        return entry

    def register_late(self, secret: str, category: Category, key: str | None) -> PlaceholderEntry:
        """Register a value discovered during redaction (an enclosing token).
        Names already written to other files are never changed: if the new value
        makes an existing name unsafe, fail closed."""
        existing = self.get(secret)
        if existing is not None:
            return existing
        entry = self.register(secret, category, key)
        v = _alnum(secret)
        if len(v) >= 6:
            for other in self.by_name.values():
                if other is entry:
                    continue
                if v in _alnum(other.name.removeprefix(PLACEHOLDER_PREFIX)) or (other.key and v in _alnum(other.key)):
                    raise RedactionError("an enclosing token would make an existing placeholder name unsafe")
        values = [x for x in (_alnum(e.secret) for e in self.by_name.values()) if len(x) >= 6]
        if any(x in _alnum(entry.name.removeprefix(PLACEHOLDER_PREFIX)) for x in values) or (
                entry.key and any(x in _alnum(entry.key) for x in values)):
            self._rename(entry, values)
        return entry

    def finalize_shared(self) -> list[PlaceholderEntry]:
        """Rename values used under unrelated keys to ``SHARED_<CATEGORY>_<fp>``.
        Keys seen at the same location are aliases (two engines, one place);
        a value is shared when two locations have no key in common."""
        renamed = []
        for ident, uses in self._uses.items():
            entry = self.by_secret.get(ident)
            if entry is None or entry.restorable:
                continue
            keysets = [k for k in uses.values() if k]
            all_keys = sorted(set().union(*keysets)) if keysets else []
            shared = any(not (a & b) for i, a in enumerate(keysets) for b in keysets[i + 1:])
            if not shared:
                continue
            entry.also_used_as = all_keys
            new = f"{PLACEHOLDER_PREFIX}SHARED_{entry.category.value}_{entry.fingerprint[:6].upper()}"
            n = 8
            while new in self.by_name and self.by_name[new] is not entry:
                new = f"{PLACEHOLDER_PREFIX}SHARED_{entry.category.value}_{entry.fingerprint[:n].upper()}"
                n += 2
            del self.by_name[entry.name]
            entry.name, entry.key = new, None
            self.by_name[new] = entry
            renamed.append(entry)
        return renamed

    def entries(self) -> list[PlaceholderEntry]:
        return sorted(self.by_name.values(), key=lambda e: e.name)

    def _rename(self, e: PlaceholderEntry, values: list[str]) -> None:
        def unsafe(text: str) -> bool:
            t = _alnum(text)
            return any(v in t for v in values)

        del self.by_name[e.name]
        e.key = None
        prefix = PLACEHOLDER_PREFIX if not e.restorable else e.name[: e.name.index("_", len("AI_SAFE_")) + 1]
        cat = f"{e.category.value}_" if prefix == PLACEHOLDER_PREFIX else ""
        for candidate in (f"{prefix}{cat}{e.fingerprint[:6].upper()}", f"{prefix}{e.fingerprint[:16].upper()}"):
            if candidate not in self.by_name and not unsafe(candidate.removeprefix(prefix)):
                break
        else:
            raise RedactionError("cannot derive a safe placeholder name")
        e.name = candidate
        self.by_name[candidate] = e

    def fix_unsafe_names(self) -> int:
        """No placeholder name (or stored key) may contain any detected value,
        compared case-insensitively and ignoring separators. Offending entries
        are renamed to a key-free ``<CATEGORY>_<fingerprint>`` form. Host
        placeholder names must not contain a label (3+ characters) of any
        registered host either."""
        values = [v for v in (_alnum(e.secret) for e in self.by_name.values()) if len(v) >= 6]
        labels = {lab for e in self.by_name.values() if e.category in (Category.HOSTNAME, Category.DOMAIN)
                  for lab in (_alnum(x) for x in re.split(r"[.\-]", e.secret.rsplit(".", 1)[0] if "." in e.secret else e.secret))
                  if len(lab) >= 3}  # the TLD reveals nothing
        checks = values + sorted(labels)

        def unsafe(e: PlaceholderEntry, text: str) -> bool:
            t = _alnum(text)
            if any(v in t for v in values):
                return True
            return e.restorable and any(lab in t for lab in labels)

        renamed = 0
        for e in list(self.by_name.values()):
            bare = re.sub(r"^AI_SAFE_[A-Z]+?_", "", e.name) if e.restorable else e.name.removeprefix(PLACEHOLDER_PREFIX)
            if not (unsafe(e, bare) or (e.key and unsafe(e, e.key))):
                continue
            self._rename(e, checks if e.restorable else values)
            renamed += 1
        return renamed


@dataclass
class RedactionOutcome:
    text: str
    replacements: int
    placeholders: list[str]


def _line_starts(text: str) -> list[int]:
    starts = [0]
    i = text.find("\n")
    while i != -1:
        starts.append(i + 1)
        i = text.find("\n", i + 1)
    return starts


def _find_all(haystack: str, needle: str, start: int = 0, end: int | None = None) -> list[tuple[int, int]]:
    out = []
    end = len(haystack) if end is None else end
    i = haystack.find(needle, start, end)
    while i != -1:
        out.append((i, i + len(needle)))
        i = haystack.find(needle, i + len(needle), end)
    return out


# ---------------------------------------------------------------------------
# Token boundaries
# ---------------------------------------------------------------------------

TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "+/_-.~")
_TOKEN_NO_SLASH = TOKEN_CHARS - {"/"}
# Inside a quoted literal, a secret-bearing token may also contain this punctuation.
_LITERAL_CHARS = TOKEN_CHARS | frozenset("!#%^&*?|,;()[]{}<>")
_QUOTES = "'\"`"
_DNS_CHARS = frozenset(string.ascii_letters + string.digits + "-.")


def _grow(text: str, s: int, e: int, chars: frozenset[str]) -> tuple[int, int]:
    a, b = s, e
    while a > 0 and text[a - 1] in chars:
        a -= 1
    while b < len(text) and text[b] in chars:
        b += 1
    return a, b


def enclosing_token(text: str, s: int, e: int) -> tuple[int, int]:
    """The token that contains ``text[s:e]``. Format prefixes and separators
    (``base64:``, ``$2y$10$``, ``Bearer ``, ``KEY=``, ``user:``, ``@host``) are
    not token characters, so they stay outside."""
    a, b = _grow(text, s, e, TOKEN_CHARS)
    if "//" in text[a:b]:  # a URL: the path segment is the token
        a, b = _grow(text, s, e, _TOKEN_NO_SLASH)
    # base64 padding
    p = b
    while p < len(text) and p - b < 2 and text[p] == "=":
        p += 1
    if p > b and (p == len(text) or (text[p] not in TOKEN_CHARS and text[p] != "=")):
        b = p
    if (a, b) != (s, e):
        # Embedded: a quoted literal without whitespace is one value as a whole.
        la, lb = _grow(text, a, b, _LITERAL_CHARS)
        if (la, lb) != (a, b) and 0 < la and lb < len(text) and text[la - 1] in _QUOTES and text[lb] == text[la - 1] \
                and "//" not in text[la:lb]:
            a, b = la, lb
    return a, b


def is_embedded(text: str, s: int, e: int) -> bool:
    return enclosing_token(text, s, e) != (s, e)


def dns_bounded(text: str, s: int, e: int, kind: str | None = None) -> bool:
    """A host / address occurrence is whole when no DNS character touches it.
    A following kept provider suffix (``.rds.amazonaws.com``) is allowed, and a
    domain (``scope: domain``) may follow subdomain labels."""
    from ai_safe.infra import PROVIDER_TAIL  # lazy: infra imports config only

    if s > 0 and text[s - 1] in _DNS_CHARS and not (kind == "domain" and text[s - 1] == "."):
        return False
    if e < len(text) and text[e] in _DNS_CHARS:
        if kind == "host" and PROVIDER_TAIL.match(text, e):
            return True
        if text[e] == "." and (e + 1 == len(text) or text[e + 1] not in _DNS_CHARS):
            return True  # sentence-ending dot, ``10.0.0.%``
        return False
    return True


def _find_all_ci(haystack: str, needle: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in re.finditer(re.escape(needle), haystack, re.IGNORECASE)]


_FORMAT_PREFIX = re.compile(r"(?i)(?:\b(?:base64|b64|hex|hex2bin):|\$2[abxy]\$\d{2}\$|\$argon2(?:id|i|d)\$[^\s'\"`$]*\$[^\s'\"`$]*\$)$")


def _key_at(text: str, pos: int) -> str | None:
    line_start = text.rfind("\n", 0, pos) + 1
    m = _FORMAT_PREFIX.search(text, line_start, pos)
    if m and m.end() == pos:
        pos = m.start()
    nl = text.find("\n", pos)
    line = text[line_start: len(text) if nl == -1 else nl]
    return key_before(line, pos - line_start)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def _remains(text: str, entry: PlaceholderEntry) -> bool:
    """True when ``entry``'s value still occurs where it must not."""
    if entry.propagate in (NONE, DNS):
        return False
    if entry.propagate == EXPAND:
        return entry.secret in text
    return any(not is_embedded(text, s, e) for s, e in _find_all(text, entry.secret))


def redact_text(
    text: str,
    rel: str,
    findings: list[Finding],
    registry: PlaceholderRegistry,
    detector: BuiltinDetector,
    global_secrets: list[str] = (),
) -> RedactionOutcome:
    for f in findings:
        if not f.exact or not f.secret:
            raise RedactionError(f"unbounded secret ({f.rule_id}) at line {f.line} cannot be redacted precisely")

    starts = _line_starts(text)
    spans: list[tuple[int, int, PlaceholderEntry]] = []
    detected: set[tuple[int, int]] = set()
    entries_here: list[PlaceholderEntry] = []

    def propagate(s: int, e: int, entry: PlaceholderEntry) -> None:
        if entry.propagate == NONE:
            return
        if entry.propagate == DNS:
            if dns_bounded(text, s, e, entry.kind):
                spans.append((s, e, entry))
                entry.files.add(rel)
            return
        a, b = enclosing_token(text, s, e)
        if (a, b) == (s, e):
            spans.append((s, e, entry))
            entry.files.add(rel)
            return
        if entry.propagate == TOKEN:
            return  # a low-entropy value inside another word: not the secret
        if b - a > MAX_EXPANDED_LEN:
            raise RedactionError("a known secret is embedded in a token that cannot be bounded")
        value = text[a:b]
        key = _key_at(text, a)
        new = registry.register_late(value, categorize("propagated-embedded", key, value, rel), key)
        new.files.add(rel)
        entries_here.append(new)
        spans.append((a, b, new))

    for f in sorted(findings, key=lambda x: (x.line, x.rule_id)):
        if is_placeholder_value(f.secret):
            continue
        entry = registry.register(f.secret, f.category, f.key)
        entry.files.add(rel)
        entries_here.append(entry)
        lo = starts[max(0, min(f.line, len(starts)) - 1)]
        hi_line = min(f.end_line, len(starts))
        hi = starts[hi_line] if hi_line < len(starts) else len(text)
        local = _find_all(text, f.secret, lo, hi)
        if not local:
            raise RedactionError(f"could not locate secret ({f.rule_id}) reported at line {f.line}")
        if entry.propagate == DNS:
            whole = [o for o in local if dns_bounded(text, *o, entry.kind)]
        else:
            whole = [o for o in local if not is_embedded(text, *o)]
        chosen = whole or local
        spans.extend((s, e, entry) for s, e in chosen)
        detected.update(chosen)
        if len(f.secret) >= FILE_REPLACE_MIN_LEN or entry.propagate == DNS:
            for o in (_find_all_ci(text, f.secret) if entry.propagate == DNS else _find_all(text, f.secret)):
                if o not in detected:
                    propagate(*o, entry)

    for secret in global_secrets:
        if len(secret) < GLOBAL_REPLACE_MIN_LEN:
            continue
        entry = registry.get(secret)
        if entry is None:
            continue
        for o in (_find_all_ci(text, entry.secret) if entry.propagate == DNS else _find_all(text, secret)):
            if o not in detected:
                propagate(*o, entry)

    if not spans:
        new_text = text
        merged: list[tuple[int, int, PlaceholderEntry]] = []
    else:
        spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        merged = []
        for s, e, entry in spans:
            if merged and s < merged[-1][1]:
                ps, pe, pentry = merged[-1]
                # keep the placeholder of the longer original span
                keep = pentry if (pe - ps) >= (e - s) else entry
                merged[-1] = (ps, max(pe, e), keep)
            else:
                merged.append((s, e, entry))
        parts = []
        last = 0
        for s, e, entry in merged:
            parts.append(text[last:s])
            parts.append(entry.token)
            entry.occurrences += 1
            last = e
        parts.append(text[last:])
        new_text = "".join(parts)

    # ---- post-redaction validation (fail closed) ----
    for f in findings:
        entry = registry.get(f.secret)
        if len(f.secret) >= CHECK_MIN_LEN and entry is not None and _remains(new_text, entry):
            raise RedactionError(f"secret ({f.rule_id}) from line {f.line} still present after redaction")
    for e in entries_here:
        if len(e.secret) >= CHECK_MIN_LEN and _remains(new_text, e):
            raise RedactionError("known secret value still present after redaction")
    for secret in global_secrets:
        entry = registry.get(secret)
        if len(secret) >= GLOBAL_REPLACE_MIN_LEN and entry is not None and _remains(new_text, entry):
            raise RedactionError("known secret value still present after redaction")
    residual = [m for m in detector.scan_text(new_text, rel) if not is_placeholder_value(m.secret)]
    if residual:
        m = residual[0]
        raise RedactionError(f"residual secret ({m.rule_id}) detected at line {m.line} after redaction")

    names = sorted({entry.name for _, _, entry in merged})
    return RedactionOutcome(text=new_text, replacements=len(merged), placeholders=names)
