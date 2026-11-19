"""Verification of an AI workspace.

Walks every entry (hidden files included, symlinks never followed) and checks:

* symlinks (escaping the workspace = CRITICAL, any symlink = ERROR when
  ``security.reject_symlinks``), special files
* Git metadata (``.git`` dirs/files, bare-repository layouts)
* credential / sensitive files (exclusion patterns)
* private keys, unresolved secrets (builtin engine + Gitleaks)
* known original credential values (keyed-fingerprint token matching)
* unexpected binaries, oversized files, unsafe permissions

Any ERROR/CRITICAL issue fails verification (non-zero exit status).
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ai_safe.classifier import match_exclude
from ai_safe.config import AISafeConfig
from ai_safe.detectors import PRIVATE_KEY_HEADER, PUTTY_KEY
from ai_safe.models import Issue, Location, Severity, is_blocking
from ai_safe.scanner import Scanner
from ai_safe.security import MARKER_FILE, hmac_fingerprint, is_binary, is_placeholder_value, is_within, symlink_target_escapes, walk_nofollow
from ai_safe.workspace import generated_paths, tree_hash

_TOKEN_SPLIT = re.compile(r"[\s\"'`,;()\[\]{}<>|]+")


def candidate_tokens(text: str) -> set[str]:
    """Substrings that could be a complete credential value."""
    out: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if 6 <= len(s) <= 512:
            out.add(s)
        for tok in _TOKEN_SPLIT.split(line):
            if len(tok) < 6:
                continue
            out.add(tok)
            for sep in ("=", ":"):
                if sep in tok:
                    a, _, b = tok.partition(sep)
                    for part in (a, b, b.rstrip(".")):
                        if len(part) >= 6:
                            out.add(part)
            m = re.match(r"^[a-z][a-z0-9+.\-]*://[^:/@]+:([^@]+)@", tok)
            if m:
                out.add(m.group(1))
            stripped = tok.strip(".:=")
            if len(stripped) >= 6:
                out.add(stripped)
    return out


def known_secret_hits(text: str, fingerprints: dict[str, str], salt: bytes) -> set[str]:
    """Return placeholder names whose original value appears in ``text``."""
    if not fingerprints:
        return set()
    hits = set()
    for tok in candidate_tokens(text):
        fp = hmac_fingerprint(tok, salt)
        if fp in fingerprints:
            hits.add(fingerprints[fp])
    return hits


@dataclass
class VerificationReport:
    workspace: str
    issues: list[Issue] = field(default_factory=list)
    files_scanned: int = 0
    engines: list[str] = field(default_factory=list)
    tree_hash: str | None = None

    @property
    def passed(self) -> bool:
        return not is_blocking(self.issues)

    def add(self, severity: Severity, code: str, path: str, message: str, line: int | None = None) -> None:
        self.issues.append(Issue(severity, code, path, message, line))

    def public(self) -> dict:
        return {
            "workspace": self.workspace,
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "engines": self.engines,
            "tree_hash": self.tree_hash,
            "issues": [i.public() for i in sorted(self.issues, key=lambda i: (-i.severity.rank, i.path))],
        }


def verify_workspace(
    ws: Path,
    cfg: AISafeConfig,
    scanner: Scanner,
    *,
    original_repo: Path | None = None,
    fingerprints: dict[str, str] | None = None,
) -> VerificationReport:
    ws = Path(ws).resolve()
    report = VerificationReport(workspace=str(ws))
    report.engines = ["builtin"] + (["gitleaks"] if scanner.gitleaks else []) + (["fingerprints"] if fingerprints else [])
    excludes = cfg.sanitization.all_excludes()
    generated = generated_paths()
    max_bytes = cfg.scanner.max_file_size_kb * 1024

    if not ws.is_dir():
        report.add(Severity.CRITICAL, "workspace-missing", str(ws), "workspace does not exist")
        return report
    if original_repo is not None and (is_within(ws, original_repo) or is_within(original_repo, ws)):
        report.add(Severity.CRITICAL, "workspace-overlap", ".", "workspace overlaps the original repository")
    if stat.S_IMODE(os.lstat(ws).st_mode) & 0o077:
        report.add(Severity.WARNING, "workspace-permissions", ".", "workspace root is accessible by other users")
    if not (ws / MARKER_FILE).is_file():
        report.add(Severity.ERROR, "marker-missing", MARKER_FILE, "workspace marker missing")

    entries = walk_nofollow(ws, max_bytes=max_bytes)
    root_children = {e.rel for e in entries if "/" not in e.rel}
    dirs = {e.rel: e for e in entries if e.kind == "dir"}
    if {"HEAD", "objects", "refs"} <= root_children:
        report.add(Severity.CRITICAL, "git-metadata", ".", "workspace root looks like a Git object store (HEAD/objects/refs)")
    for e in entries:
        rel = e.rel
        name = rel.rsplit("/", 1)[-1]
        if e.kind == "dir":
            if name.casefold() == ".git":
                report.add(Severity.CRITICAL, "git-metadata", rel, "Git metadata directory present in AI workspace")
            elif {"HEAD", "objects", "refs"} <= set(e.children):
                report.add(Severity.CRITICAL, "git-metadata", rel, "directory looks like a Git object store (HEAD/objects/refs)")
            continue
        if any(part.casefold() == ".git" for part in rel.split("/")[:-1]):
            continue  # already reported at the directory level
        if e.kind == "symlink":
            if symlink_target_escapes(rel, e.link_target, ws):
                report.add(Severity.CRITICAL, "symlink-escape", rel, "symlink points outside the workspace")
            elif cfg.security.reject_symlinks:
                report.add(Severity.ERROR, "symlink", rel, "symlink present (security.reject_symlinks)")
            continue
        if e.kind in ("special", "unreadable"):
            report.add(Severity.ERROR, "special-file", rel, "special or unreadable file in workspace")
            continue
        st = e.st
        if name.casefold() == ".git":
            report.add(Severity.CRITICAL, "git-metadata", rel, "'.git' file (gitdir pointer) present in AI workspace")
            continue
        if st.st_nlink > 1:
            report.add(Severity.ERROR, "hard-link", rel, "hard-linked file (may alias a file outside the workspace)")
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            report.add(Severity.WARNING, "setuid", rel, "setuid/setgid bit set")
        if st.st_mode & stat.S_IWOTH:
            report.add(Severity.WARNING, "world-writable", rel, "world-writable file")
        if rel in generated:
            pass
        elif rel.startswith(".claude/"):
            if rel == ".claude/settings.local.json":
                report.add(Severity.WARNING, "claude-local-settings", rel, "Claude Code local settings created in workspace (not integrated)")
            else:
                report.add(Severity.ERROR, "unexpected-claude-file", rel, "unexpected file under .claude/ (may contain hooks or credentials)")
        else:
            pat = match_exclude(rel, excludes)
            if pat:
                report.add(Severity.ERROR, "credential-file", rel, f"sensitive/credential file present (matches {pat!r})")
        if e.data is None:
            report.add(Severity.ERROR, "too-large", rel, "file larger than scanner.max_file_size_kb cannot be verified")
            continue
        data = e.data
        report.files_scanned += 1
        if is_binary(data):
            text = data.decode("latin-1")
            if Path(name).suffix.lower() not in cfg.sanitization.allowed_binary_extensions:
                report.add(Severity.ERROR, "unexpected-binary", rel, "unexpected binary file")
        else:
            text = data.decode("utf-8")
        _check_text(report, scanner, text, rel, fingerprints)

    if scanner.gitleaks:
        for rec in scanner.gitleaks.scan_dir(ws):
            f = scanner.from_gitleaks(rec, Location.WORKSPACE)
            if f is None or is_placeholder_value(f.secret):
                continue
            report.add(Severity.CRITICAL, "gitleaks", f.file, f"unresolved secret detected by gitleaks ({f.rule_id}, {f.category.value})", f.line)

    report.tree_hash = tree_hash(ws)
    return report


def _check_text(report: VerificationReport, scanner: Scanner, text: str, rel: str, fingerprints: dict[str, str] | None) -> None:
    for m in PRIVATE_KEY_HEADER.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        report.add(Severity.CRITICAL, "private-key", rel, "private key material present", line)
    if PUTTY_KEY.search(text):
        report.add(Severity.CRITICAL, "private-key", rel, "PuTTY private key present")
    for m in scanner.detector.scan_text(text, rel):
        if m.rule_id.startswith("private-key") or is_placeholder_value(m.secret):
            continue
        report.add(Severity.CRITICAL, "unresolved-secret", rel, f"unresolved secret ({m.rule_id}, {m.category.value})", m.line)
    if fingerprints:
        for name in sorted(known_secret_hits(text, fingerprints, scanner.salt)):
            report.add(Severity.CRITICAL, "known-secret", rel, f"original credential value for {name} is present")
