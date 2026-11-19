"""Redaction engine.

Gitleaks (and the builtin detector) *detect*; this module *redacts*:

1. every finding must be exact (bounded) - otherwise fail closed;
2. every occurrence of each detected secret is located in the file content;
3. overlapping spans are merged and replaced by a deterministic placeholder
   ``${AI_SAFE_SECRET_<NAME>}``;
4. the result is re-scanned; any residual secret, or any detected value still
   present, raises :class:`RedactionError` and the caller excludes the file.

Placeholders are derived from the assignment key (``DB_PASSWORD`` ->
``AI_SAFE_SECRET_DB_PASSWORD``) or, without a key, from the category plus a
keyed fingerprint. The same secret always maps to the same placeholder.
"""

from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass, field

from ai_safe.classifier import key_words
from ai_safe.detectors import BuiltinDetector, is_plausible_key
from ai_safe.models import Category, Finding
from ai_safe.security import PLACEHOLDER_PREFIX, hmac_fingerprint, is_placeholder_value

GLOBAL_REPLACE_MIN_LEN = 8   # replace anywhere in any file
FILE_REPLACE_MIN_LEN = 6     # replace anywhere in the file where it was found
CHECK_MIN_LEN = 6            # post-redaction "value still present" check


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

    @property
    def token(self) -> str:
        return "${" + self.name + "}"


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


class PlaceholderRegistry:
    def __init__(self, salt: bytes, deterministic: bool = True) -> None:
        self.salt = salt
        self.deterministic = deterministic
        self.by_secret: dict[str, PlaceholderEntry] = {}
        self.by_name: dict[str, PlaceholderEntry] = {}

    def get(self, secret: str) -> PlaceholderEntry | None:
        return self.by_secret.get(secret)

    def register(self, secret: str, category: Category, key: str | None) -> PlaceholderEntry:
        if secret in self.by_secret:
            return self.by_secret[secret]
        fp = hmac_fingerprint(secret, self.salt)
        if key is not None and (not is_plausible_key(key) or _overlaps(key, secret)):
            key = None
        suffix_src = fp if self.deterministic else _secrets.token_hex(12)
        base = _normalise_key(key) if key else ""
        if base:
            name = PLACEHOLDER_PREFIX + base
            if name in self.by_name:
                name = f"{name}_{suffix_src[:6].upper()}"
        else:
            name = f"{PLACEHOLDER_PREFIX}{category.value}_{suffix_src[:6].upper()}"
        n = 8
        while name in self.by_name:
            name = f"{PLACEHOLDER_PREFIX}{base or category.value}_{suffix_src[:n].upper()}"
            n += 2
        entry = PlaceholderEntry(name=name, category=category, fingerprint=fp, key=key, secret=secret)
        self.by_secret[secret] = entry
        self.by_name[name] = entry
        return entry

    def entries(self) -> list[PlaceholderEntry]:
        return sorted(self.by_name.values(), key=lambda e: e.name)

    def fix_unsafe_names(self) -> int:
        """No placeholder name (or stored key) may contain any detected value,
        compared case-insensitively and ignoring separators. Offending entries
        are renamed to a key-free ``<CATEGORY>_<fingerprint>`` form."""
        values = [v for v in (_alnum(e.secret) for e in self.by_name.values()) if len(v) >= 6]

        def unsafe(text: str) -> bool:
            t = _alnum(text)
            return any(v in t for v in values)

        renamed = 0
        for e in list(self.by_name.values()):
            if not (unsafe(e.name.removeprefix(PLACEHOLDER_PREFIX)) or (e.key and unsafe(e.key))):
                continue
            del self.by_name[e.name]
            e.key = None
            for candidate in (f"{PLACEHOLDER_PREFIX}{e.category.value}_{e.fingerprint[:6].upper()}",
                              f"{PLACEHOLDER_PREFIX}{e.fingerprint[:16].upper()}"):
                if candidate not in self.by_name and not unsafe(candidate.removeprefix(PLACEHOLDER_PREFIX)):
                    break
            else:
                raise RedactionError("cannot derive a safe placeholder name")
            e.name = candidate
            self.by_name[candidate] = e
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
    for f in sorted(findings, key=lambda x: (x.line, x.rule_id)):
        if is_placeholder_value(f.secret):
            continue
        entry = registry.register(f.secret, f.category, f.key)
        entry.files.add(rel)
        if len(f.secret) >= FILE_REPLACE_MIN_LEN:
            occ = _find_all(text, f.secret)
        else:
            lo = starts[max(0, min(f.line, len(starts)) - 1)]
            hi_line = min(f.end_line, len(starts))
            hi = starts[hi_line] if hi_line < len(starts) else len(text)
            occ = _find_all(text, f.secret, lo, hi)
        if not occ:
            raise RedactionError(f"could not locate secret ({f.rule_id}) reported at line {f.line}")
        spans.extend((s, e, entry) for s, e in occ)

    for secret in global_secrets:
        if len(secret) < GLOBAL_REPLACE_MIN_LEN:
            continue
        entry = registry.get(secret)
        if entry is None:
            continue
        occ = _find_all(text, secret)
        if occ:
            entry.files.add(rel)
            spans.extend((s, e, entry) for s, e in occ)

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
        if len(f.secret) >= CHECK_MIN_LEN and f.secret in new_text:
            raise RedactionError(f"secret ({f.rule_id}) from line {f.line} still present after redaction")
    for secret in global_secrets:
        if len(secret) >= GLOBAL_REPLACE_MIN_LEN and secret in new_text:
            raise RedactionError("known secret value still present after redaction")
    residual = [m for m in detector.scan_text(new_text, rel) if not is_placeholder_value(m.secret)]
    if residual:
        m = residual[0]
        raise RedactionError(f"residual secret ({m.rule_id}) detected at line {m.line} after redaction")

    names = sorted({entry.name for _, _, entry in merged})
    return RedactionOutcome(text=new_text, replacements=len(merged), placeholders=names)
