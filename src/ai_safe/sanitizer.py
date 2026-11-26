"""Sanitization: build the AI workspace from the original repository.

For every candidate file (tracked + untracked, optionally ignored):

* unsafe names, Git metadata, sensitive paths (``.env``, keys, credential
  stores, configured excludes), symlinks, special files, oversized files and
  non-allowlisted binaries are **excluded**;
* text files are redacted by :mod:`ai_safe.redaction` using scanner findings;
* any redaction doubt (unbounded secret, value not located, residual
  detection) **excludes** the file (fail closed);
* a final sweep re-reads every written file and removes any file that still
  contains a known secret value.

The manifest records what happened to every file - never secret values.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ai_safe import git_history as gh
from ai_safe.classifier import ClaudePath, claude_path_policy, sensitive_match
from ai_safe.config import AISafeConfig
from ai_safe.detectors import PRIVATE_KEY_HEADER, PUTTY_KEY
from ai_safe.credential_map import CredentialMap
from ai_safe.models import WORKING_TREE_LOCATIONS, Finding, Location
from ai_safe.redaction import CHECK_MIN_LEN, PlaceholderRegistry, RedactionError, redact_text
from ai_safe.scanner import Scanner, ScanResult
from ai_safe.security import (
    REDACTOR,
    SecurityError,
    is_binary,
    is_git_metadata_path,
    is_placeholder_value,
    keyed_digest,
    safe_file_mode,
    safe_relpath,
    secure_remove_file,
    sha256_bytes,
    symlink_escapes,
    write_private_file,
)
from ai_safe.workspace import (
    HISTORY_SUMMARY_FILE,
    PLACEHOLDERS_FILE,
    CLAUDE_SETTINGS,
    Session,
    claude_settings,
    claude_settings_text,
    generated_paths,
    install_claude_integration,
    merge_claude_settings,
    take_snapshot,
)


@dataclass
class ManifestEntry:
    path: str
    action: str  # sanitized | copied | excluded | generated | merged
    reason: str | None = None
    replacements: int = 0
    placeholders: list[str] = field(default_factory=list)
    sha256: str | None = None          # of the sanitized content (workspace copy)
    original_digest: str | None = None  # keyed HMAC of the original bytes
    mode: int | None = None


@dataclass
class SanitizeResult:
    session: Session
    entries: list[ManifestEntry]
    registry: PlaceholderRegistry
    credential_map: CredentialMap
    warnings: list[str] = field(default_factory=list)

    @property
    def excluded(self) -> list[ManifestEntry]:
        return [e for e in self.entries if e.action == "excluded"]

    @property
    def sanitized(self) -> list[ManifestEntry]:
        return [e for e in self.entries if e.action == "sanitized"]

    @property
    def copied(self) -> list[ManifestEntry]:
        return [e for e in self.entries if e.action == "copied"]


def _is_private_key_file(text: str) -> bool:
    head = text.lstrip()[:200]
    return bool(re.match(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY", head)) or head.startswith("PuTTY-User-Key-File-")


class Sanitizer:
    def __init__(self, cfg: AISafeConfig, scanner: Scanner, salt: bytes) -> None:
        self.cfg = cfg
        self.scanner = scanner
        self.salt = salt
        self.excludes = cfg.sanitization.all_excludes()
        self._team_settings: dict | None = None

    def candidates(self, scan: ScanResult) -> list[str]:
        dummy = ScanResult(root=scan.root, is_git=scan.is_git)
        files = self.scanner.list_files(scan.root, scan.is_git, dummy)
        out = []
        for rel, loc in files.items():
            if loc == Location.IGNORED and not self.cfg.sanitization.include_ignored_files:
                continue
            out.append(rel)
        return sorted(out)

    def run(self, scan: ScanResult, session: Session, *, passphrase: str | None = None) -> SanitizeResult:
        root = scan.root
        ws = session.workspace_path
        self._team_settings = None  # never carry one repository's settings into another run
        registry = PlaceholderRegistry(self.salt, self.cfg.sanitization.placeholders.deterministic)

        # Pre-register in a deterministic order: working-tree findings first.
        exact = [f for f in scan.findings if f.exact and f.secret]
        wt = sorted((f for f in exact if f.location in WORKING_TREE_LOCATIONS), key=lambda f: (f.file, f.line, f.rule_id))
        other = sorted((f for f in exact if f.location not in WORKING_TREE_LOCATIONS), key=lambda f: (f.location.value, f.file, f.line, f.rule_id))
        for f in wt + other:
            registry.register(f.secret, f.category, f.key)
        try:
            registry.fix_unsafe_names()
        except RedactionError:
            raise SecurityError("could not derive safe placeholder names - aborting (fail closed)") from None
        global_secrets = sorted({f.secret for f in exact}, key=len, reverse=True)

        by_file: dict[str, list[Finding]] = {}
        for f in scan.findings:
            if f.location in WORKING_TREE_LOCATIONS:
                by_file.setdefault(f.file, []).append(f)

        entries: list[ManifestEntry] = []
        for rel in self.candidates(scan):
            entries.append(self._process(root, ws, rel, by_file.get(rel, []), registry, global_secrets))

        warnings = self._final_sweep(ws, entries, registry)
        state_root_path = Path(session.state_dir).parent.parent
        warnings += self._sweep_merged_settings(state_root_path, entries, registry, global_secrets)

        if self.cfg.sanitization.history_summary and scan.is_git:
            text = history_summary(root, self.scanner, registry, self.cfg.sanitization.history_summary_max_commits)
            write_private_file(ws / HISTORY_SUMMARY_FILE, text, mode=0o644)
            entries.append(ManifestEntry(HISTORY_SUMMARY_FILE, "generated", "sanitized Git history summary", sha256=sha256_bytes(text.encode())))

        cmap = CredentialMap.from_registry(registry)
        placeholders_doc = _placeholders_doc(cmap)
        write_private_file(ws / PLACEHOLDERS_FILE, placeholders_doc, mode=0o644)
        install_claude_integration(ws, state_root_path, self.cfg, self._team_settings)

        cmap.save(session.state_path, registry, store_secret_values=self.cfg.security.store_secret_values, passphrase=passphrase)
        manifest = {
            "version": 1,
            "session_id": session.id,
            "created_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
            "is_git_repository": scan.is_git,
            "files": [asdict(e) for e in entries],
            "summary": {
                "sanitized": sum(1 for e in entries if e.action == "sanitized"),
                "copied": sum(1 for e in entries if e.action == "copied"),
                "excluded": sum(1 for e in entries if e.action == "excluded"),
                "placeholders": len(cmap.entries),
            },
        }
        write_private_file(session.manifest_path, json.dumps(manifest, indent=2))
        take_snapshot(ws, session.snapshot_dir)
        session.status = "sanitized"
        session.history_only_secrets = len({f.fingerprint for f in scan.secrets_only_in_history})
        session.save()
        return SanitizeResult(session, entries, registry, cmap, warnings)

    # ------------------------------------------------------------------

    def _process(self, root: Path, ws: Path, rel: str, findings: list[Finding],
                 registry: PlaceholderRegistry, global_secrets: list[str]) -> ManifestEntry:
        def excluded(reason: str, digest: str | None = None) -> ManifestEntry:
            return ManifestEntry(rel, "excluded", reason, original_digest=digest)

        try:
            relp = safe_relpath(rel)
        except SecurityError as exc:
            return excluded(f"unsafe path name: {exc}")
        if is_git_metadata_path(relp):
            return excluded("git metadata")
        is_settings = claude_path_policy(rel) is ClaudePath.SETTINGS
        if is_settings:
            if not self.cfg.workspace.generate_claude_settings:
                return excluded("team .claude/settings.json not merged (workspace.generate_claude_settings is false)")
            if self._team_settings is not None:
                return excluded("duplicate .claude/settings.json (not merged)")
        elif str(relp) in generated_paths():
            return excluded("reserved ai-safe path")
        pat = sensitive_match(rel, self.excludes)
        if pat:
            return excluded(f"sensitive path (matches {pat!r})")
        src = root / rel
        try:
            st = os.lstat(src)
        except FileNotFoundError:
            return excluded("missing from working tree")
        dst = ws / rel
        if stat.S_ISLNK(st.st_mode):
            if self.cfg.security.reject_symlinks or symlink_escapes(src, root):
                return excluded("symlink (rejected)")
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(os.readlink(src), dst)
            return ManifestEntry(rel, "copied", "internal symlink")
        if not stat.S_ISREG(st.st_mode):
            return excluded("not a regular file")
        if st.st_size > self.cfg.scanner.max_file_size_kb * 1024:
            return excluded("larger than scanner.max_file_size_kb (cannot be verified)")
        data = src.read_bytes()
        digest = keyed_digest(data, self.salt)
        mode = safe_file_mode(st.st_mode, self.cfg.sanitization.preserve_permissions)

        if is_binary(data):
            if is_settings:
                return excluded("binary .claude/settings.json (not merged)", digest)
            ext = Path(rel).suffix.lower()
            if ext not in self.cfg.sanitization.allowed_binary_extensions:
                return excluded("binary file (not in sanitization.allowed_binary_extensions)", digest)
            latin = data.decode("latin-1")
            if findings or "PRIVATE KEY" in latin or self.scanner.detector.scan_text(latin, rel):
                return excluded("binary file contains credential-like data", digest)
            if any(len(s) >= CHECK_MIN_LEN and s in latin for s in global_secrets):
                return excluded("binary file contains a known secret value", digest)
            self._write(dst, data, mode)
            return ManifestEntry(rel, "copied", "allowlisted binary", sha256=sha256_bytes(data), original_digest=digest, mode=mode)

        text = data.decode("utf-8")
        if _is_private_key_file(text):
            return excluded("private key file", digest)
        if findings and not self.cfg.sanitization.placeholders.enabled:
            return excluded("contains credentials and placeholders are disabled", digest)
        try:
            outcome = redact_text(text, rel, findings, registry, self.scanner.detector, global_secrets)
        except RedactionError as exc:
            return excluded(f"unresolved secret - fail closed ({exc})", digest)
        if is_settings:
            # Never written here: install_claude_integration writes the merged file.
            try:
                parsed = json.loads(outcome.text)
            except ValueError:
                return excluded("invalid JSON in .claude/settings.json (not merged)", digest)
            if not isinstance(parsed, dict):
                return excluded("invalid JSON in .claude/settings.json: not an object (not merged)", digest)
            self._team_settings = parsed
            return ManifestEntry(rel, "merged", "merged into generated .claude/settings.json",
                                 outcome.replacements, outcome.placeholders, original_digest=digest)
        out = outcome.text.encode("utf-8")
        self._write(dst, out, mode)
        action = "sanitized" if outcome.replacements else "copied"
        return ManifestEntry(rel, action, None, outcome.replacements, outcome.placeholders, sha256_bytes(out), digest, mode)

    @staticmethod
    def _write(dst: Path, data: bytes, mode: int) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(dst, mode)

    def _sweep_merged_settings(self, state_root_path: Path, entries: list[ManifestEntry],
                               registry: PlaceholderRegistry, global_secrets: list[str]) -> list[str]:
        """Check the exact merged settings text before it is written.

        Redaction ran on the raw team JSON; decoding (``\\uXXXX``, ``\\/``) and
        re-serialising can surface values that redaction never saw. Any known
        secret value or detector hit in the final text drops the team settings
        (generated-only settings are written instead) - fail closed.
        """
        if self._team_settings is None:
            return []
        merged = merge_claude_settings(self._team_settings, claude_settings(state_root_path))
        written = claude_settings_text(merged)
        decoded = json.dumps(merged, indent=2, ensure_ascii=False)
        known = {e.secret for e in registry.entries() if len(e.secret) >= CHECK_MIN_LEN}
        known |= {s for s in global_secrets if len(s) >= CHECK_MIN_LEN}
        hit = False
        for text in (written, decoded):
            if any(s in text for s in known) or PRIVATE_KEY_HEADER.search(text) or PUTTY_KEY.search(text):
                hit = True
            elif any(not is_placeholder_value(m.secret) for m in self.scanner.detector.scan_text(text, CLAUDE_SETTINGS)):
                hit = True
        if not hit:
            return []
        self._team_settings = None
        for e in entries:
            if e.action == "merged":
                e.action = "excluded"
                e.reason = "credential-like value in merged .claude/settings.json - fail closed (not merged)"
                e.replacements, e.placeholders = 0, []
        return [f"{CLAUDE_SETTINGS}: team settings not merged (credential-like value after JSON decoding)"]

    def _final_sweep(self, ws: Path, entries: list[ManifestEntry], registry: PlaceholderRegistry) -> list[str]:
        """Remove any written file that still contains a known secret value."""
        secrets_ = [e.secret for e in registry.entries() if len(e.secret) >= CHECK_MIN_LEN]
        if not secrets_:
            return []
        pattern = re.compile("|".join(re.escape(s) for s in sorted(secrets_, key=len, reverse=True)))
        warnings = []
        for e in entries:
            if e.action not in ("sanitized", "copied"):
                continue
            p = ws / e.path
            if p.is_symlink() or not p.is_file():
                continue
            content = p.read_bytes().decode("utf-8", "replace") if not is_binary(p.read_bytes()) else p.read_bytes().decode("latin-1")
            if pattern.search(content):
                secure_remove_file(p, shred=True)
                e.action, e.reason, e.sha256 = "excluded", "known secret value still present after redaction - fail closed", None
                warnings.append(f"{e.path}: removed from workspace (known secret value present)")
        return warnings


def history_summary(repo: Path, scanner: Scanner, registry: PlaceholderRegistry, max_commits: int) -> str:
    """Sanitized summary of Git history: no diffs, no authors, redacted subjects."""
    stats = gh.history_stats(repo)
    lines = [
        "# Sanitized Git history summary",
        "",
        "Generated by ai-safe. Contains commit subjects (redacted) and changed paths only:",
        "no diffs, no file contents, no author names or e-mails. The original history",
        "is not available in this workspace.",
        "",
        f"- Commits (all refs): {stats.commits}",
        f"- Branches: {stats.branches}",
        f"- Tags: {stats.tags}",
        "",
    ]
    known = sorted((e for e in registry.entries() if len(e.secret) >= 4), key=lambda e: len(e.secret), reverse=True)
    for c in gh.commit_summaries(repo, max_commits):
        subject = c.subject
        for e in known:
            subject = subject.replace(e.secret, e.token)
        for m in sorted(scanner.detector.scan_text(subject, "<subject>"), key=lambda m: m.start, reverse=True):
            subject = subject[: m.start] + "[REDACTED]" + subject[m.end:]
        subject = REDACTOR.redact(subject)
        lines.append(f"## {c.short} - {c.date}")
        lines.append("")
        lines.append(subject.replace("\n", " "))
        lines.append("")
        for status, path in c.files[:200]:
            lines.append(f"- `{status}` {path}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _placeholders_doc(cmap: CredentialMap) -> str:
    lines = [
        "# AI-safe placeholders",
        "",
        "Real credentials in this workspace were replaced by placeholders of the form",
        "`${AI_SAFE_SECRET_<NAME>}`. Values are not available here and must not be guessed,",
        "requested or recovered. Code should read credentials from environment variables or a",
        "secret manager; report any new credential you need as a placeholder requirement.",
        "",
        "| Placeholder | Category | Files |",
        "|---|---|---|",
    ]
    for e in cmap.entries:
        if not e.files:
            continue
        lines.append(f"| `{e.placeholder}` | {e.category} | {', '.join(e.files[:10])} |")
    return "\n".join(lines) + "\n"
