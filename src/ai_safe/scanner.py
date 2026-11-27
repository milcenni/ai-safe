"""Secret discovery across the working tree, the index and Git history.

Two engines run side by side:

* **gitleaks** (when ``scanner.engine == gitleaks``): ``dir`` for files on disk,
  ``git --staged`` / ``git --pre-commit`` for index/worktree changes and
  ``git --log-opts=--all`` for every reachable commit.
* **builtin** (always, unless ``scanner.builtin_rules: false``): provider
  token formats, private keys, key/value assignments, custom rules.

Findings are classified, fingerprinted with a keyed HMAC and deduplicated.
Secret values stay in memory and are registered with the global redactor so
they can never be printed.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ai_safe import git_history as gh
from ai_safe.classifier import ClaudePath, categorize, claude_path_policy, is_pristine_ai_safe_skill
from ai_safe.config import AISafeConfig
from ai_safe.detectors import BuiltinDetector, key_before
from ai_safe.gitleaks import Gitleaks, load_report
from ai_safe.models import Category, Finding, Location
from ai_safe.php_dataflow import trace_php
from ai_safe.security import REDACTOR, hmac_fingerprint, is_binary, is_placeholder_value


@dataclass
class ScanResult:
    root: Path
    is_git: bool
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    engines: list[str] = field(default_factory=list)
    history_scanned: bool = False
    history_commits: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_location(self) -> Counter:
        return Counter(f.location.value for f in self.findings)

    def by_category(self) -> Counter:
        return Counter(f.category.value for f in self.findings)

    @property
    def history_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.location == Location.HISTORY]

    @property
    def secrets_only_in_history(self) -> list[Finding]:
        """History findings whose value is no longer present in the working tree."""
        current = {f.fingerprint for f in self.findings if f.location != Location.HISTORY}
        return [f for f in self.history_findings if f.fingerprint not in current]

    def public(self) -> dict:
        return {
            "root": str(self.root),
            "is_git_repository": self.is_git,
            "engines": self.engines,
            "files_scanned": self.files_scanned,
            "history_scanned": self.history_scanned,
            "history_commits": self.history_commits,
            "summary": {
                "total": len(self.findings),
                "by_location": dict(self.by_location()),
                "by_category": dict(self.by_category()),
                "unique_secrets": len({f.fingerprint for f in self.findings}),
                "history_only_secrets": len({f.fingerprint for f in self.secrets_only_in_history}),
            },
            "findings": [f.public() for f in self.findings],
            "skipped": [{"path": p, "reason": r} for p, r in self.skipped],
            "warnings": self.warnings,
        }


class Scanner:
    def __init__(self, cfg: AISafeConfig, salt: bytes, gitleaks: Gitleaks | None = None) -> None:
        self.cfg = cfg
        self.salt = salt
        self.detector = BuiltinDetector(cfg.scanner.custom_rules, enable_builtin=cfg.scanner.builtin_rules,
                                        emails=cfg.sanitization.sanitize_emails)
        if gitleaks is None and cfg.scanner.engine == "gitleaks":
            gitleaks = Gitleaks.require(cfg.scanner.gitleaks_path, cfg.scanner.timeout_seconds)
        self.gitleaks = gitleaks

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _finding(self, *, rule_id, category, file, line, end_line, engine, location, key=None,
                 commit=None, exact=True, secret="") -> Finding:
        REDACTOR.add(secret)
        return Finding(
            rule_id=rule_id, category=category, file=file, line=line, end_line=end_line,
            engine=engine, location=location, key=key, commit=commit, exact=exact, secret=secret,
            fingerprint=hmac_fingerprint(secret, self.salt) if secret else "",
        )

    def detect_text(self, text: str, rel: str, location: Location, *, line_offset: int = 0,
                    commit: str | None = None) -> list[Finding]:
        out = []
        lines: list[str] | None = None
        for m in self.detector.scan_text(text, rel):
            key = m.key
            if key is None and m.category.value not in ("PRIVATE_KEY", "SSH_KEY"):
                if lines is None:
                    lines = text.split("\n")
                line_start = text.rfind("\n", 0, m.start) + 1
                key = key_before(lines[m.line - 1], m.start - line_start) if m.line - 1 < len(lines) else None
            out.append(self._finding(
                rule_id=m.rule_id, category=m.category, file=rel, line=m.line + line_offset,
                end_line=m.end_line + line_offset, engine=m.engine, location=location,
                key=key, commit=commit, exact=m.exact, secret=m.secret,
            ))
        return out

    def from_gitleaks(self, rec: dict, location: Location, text_by_file: dict[str, str] | None = None) -> Finding | None:
        secret = str(rec.get("Secret") or "")
        if not secret or is_placeholder_value(secret) or "AI_SAFE_SECRET_" in secret:
            return None
        file = str(rec.get("File", ""))
        line = int(rec.get("StartLine") or 1)
        end_line = int(rec.get("EndLine") or line)
        key = None
        if text_by_file is not None and file in text_by_file:
            lines = text_by_file[file].split("\n")
            if 0 < line <= len(lines):
                col = lines[line - 1].find(secret.split("\n")[0])
                if col >= 0:
                    key = key_before(lines[line - 1], col)
        else:
            match = str(rec.get("Match") or "")
            idx = match.find(secret)
            if idx > 0:
                key = key_before(match, idx)
        rule = str(rec.get("RuleID", "gitleaks"))
        return self._finding(
            rule_id=rule, category=categorize(rule, key, secret, file), file=file, line=line,
            end_line=end_line, engine="gitleaks", location=location, key=key,
            commit=(str(rec.get("Commit") or "")[:12] or None), secret=secret,
        )

    # ------------------------------------------------------------------
    # Repository scan
    # ------------------------------------------------------------------

    def _read_text(self, path: Path, rel: str, result: ScanResult) -> str | None:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if not os.path.isfile(path) or os.path.islink(path):
            result.skipped.append((rel, "not a regular file"))
            return None
        if st.st_size > self.cfg.scanner.max_file_size_kb * 1024:
            result.skipped.append((rel, "larger than scanner.max_file_size_kb"))
            return None
        data = path.read_bytes()
        if is_binary(data):
            # Binary files are not pattern-scanned (except via gitleaks); they
            # are excluded from the AI workspace unless explicitly allowed.
            text = data.decode("latin-1")
            if "PRIVATE KEY-----" not in text:
                return None
            return text
        return data.decode("utf-8")

    @staticmethod
    def _skip(root: Path, rel: str) -> bool:
        """ai-safe's own install dirs and unmodified ai-safe skills are not scanned.

        A modified ai-safe skill is scanned like any other file.
        """
        return claude_path_policy(rel) == ClaudePath.INSTALL or is_pristine_ai_safe_skill(root, rel)

    def list_files(self, root: Path, is_git: bool, result: ScanResult) -> dict[str, Location]:
        files = self._list_files(root, is_git, result)
        return {rel: loc for rel, loc in files.items() if not self._skip(root, rel)}

    def _list_files(self, root: Path, is_git: bool, result: ScanResult) -> dict[str, Location]:
        files: dict[str, Location] = {}
        if is_git:
            for f in gh.list_tracked(root):
                files[f] = Location.TRACKED
            if self.cfg.scanner.scan_untracked:
                for f in gh.list_untracked(root):
                    files[f] = Location.UNTRACKED
            if self.cfg.scanner.scan_ignored:
                for entry in gh.list_ignored(root):
                    if entry.endswith("/"):
                        for f in self._walk(root / entry, root, result):
                            files.setdefault(f, Location.IGNORED)
                    else:
                        files.setdefault(entry, Location.IGNORED)
        else:
            for f in self._walk(root, root, result):
                files[f] = Location.FILESYSTEM
        return files

    def _walk(self, start: Path, root: Path, result: ScanResult) -> list[str]:
        out = []
        skip = set(self.cfg.scanner.ignored_skip_dirs)
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if d == ".git":
                    continue
                if d in skip:
                    result.skipped.append((rel + "/", "skipped directory (scanner.ignored_skip_dirs)"))
                    continue
                if os.path.islink(full):
                    out.append(rel)
                    continue
                keep.append(d)
            dirnames[:] = keep
            for f in filenames:
                out.append(os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/"))
        return out

    def scan(self, root: Path, *, include_history: bool | None = None,
             gitleaks_report: Path | None = None) -> ScanResult:
        root = Path(root).resolve()
        is_git = gh.is_git_repo(root)
        if is_git:
            root = gh.repo_root(root)
        result = ScanResult(root=root, is_git=is_git)
        result.engines = ["builtin" if self.cfg.scanner.builtin_rules else "custom-rules"]
        if self.gitleaks:
            result.engines.insert(0, "gitleaks")
        if include_history is None:
            include_history = self.cfg.scanner.scan_git_history

        files = self.list_files(root, is_git, result)
        texts: dict[str, str] = {}
        findings: list[Finding] = []

        # 1. Working tree (tracked / untracked / ignored files on disk)
        for rel, loc in sorted(files.items()):
            text = self._read_text(root / rel, rel, result)
            if text is None:
                continue
            texts[rel] = text
            result.files_scanned += 1
            findings.extend(self.detect_text(text, rel, loc))

        # 1b. PHP dataflow: credential-call arguments traced across the working tree
        if self.cfg.scanner.php_dataflow != "off":
            flow, flow_warnings = trace_php(texts)
            for ff in flow:
                findings.append(self._finding(
                    rule_id=ff.rule_id, category=ff.category, file=ff.file, line=ff.line, end_line=ff.line,
                    engine="builtin", location=files[ff.file], key=ff.key, secret=ff.secret,
                ))
            result.warnings.extend(str(w) for w in flow_warnings)

        if self.gitleaks:
            for rec in self.gitleaks.scan_dir(root):
                rel = rec["File"]
                if self._skip(root, rel):
                    continue
                loc = files.get(rel)
                if loc is None:
                    if not self.cfg.scanner.scan_ignored and is_git:
                        continue
                    loc = Location.IGNORED if is_git else Location.FILESYSTEM
                f = self.from_gitleaks(rec, loc, texts)
                if f:
                    findings.append(f)

        if is_git:
            # 2. Staged changes (index content)
            if self.cfg.scanner.scan_staged:
                for chunk in gh.staged_added_chunks(root):
                    findings.extend(self.detect_text(chunk.text, chunk.path, Location.STAGED, line_offset=chunk.start_line - 1))
                if self.gitleaks:
                    for rec in self.gitleaks.scan_staged(root):
                        f = self.from_gitleaks(rec, Location.STAGED)
                        if f:
                            findings.append(f)
            # 3. Unstaged changes (worktree vs index)
            if self.cfg.scanner.scan_unstaged:
                for chunk in gh.unstaged_added_chunks(root):
                    findings.extend(self.detect_text(chunk.text, chunk.path, Location.UNSTAGED, line_offset=chunk.start_line - 1))
                if self.gitleaks:
                    for rec in self.gitleaks.scan_unstaged(root):
                        f = self.from_gitleaks(rec, Location.UNSTAGED)
                        if f:
                            findings.append(f)
            # 4. Full history: all branches, tags, deleted files
            if include_history:
                result.history_scanned = True
                result.history_commits = gh.history_stats(root).commits
                opts = self.cfg.scanner.history_log_opts
                for chunk in gh.history_added_chunks(root, opts, timeout=self.cfg.scanner.timeout_seconds):
                    findings.extend(self.detect_text(chunk.text, chunk.path, Location.HISTORY,
                                                     line_offset=chunk.start_line - 1, commit=(chunk.commit or "")[:12] or None))
                if self.cfg.scanner.scan_commit_messages:
                    for sha, msg in gh.commit_messages(root, opts):
                        findings.extend(self.detect_text(msg, "<commit-message>", Location.HISTORY, commit=sha[:12]))
                if self.gitleaks:
                    for rec in self.gitleaks.scan_git(root, opts):
                        f = self.from_gitleaks(rec, Location.HISTORY)
                        if f:
                            findings.append(f)

        if gitleaks_report is not None:
            for rec in load_report(gitleaks_report):
                loc = Location.HISTORY if rec.get("Commit") else Location.IMPORTED
                f = self.from_gitleaks(rec, loc)
                if f:
                    findings.append(f)

        result.findings = dedupe_findings(findings)
        return result


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicates reported by both engines (same place, same secret)."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.location, f.file, f.line, f.commit, f.fingerprint or f.rule_id)
        if k in seen:
            prev = seen[k]
            if f.engine not in prev.engine.split("+"):
                prev.engine = prev.engine + "+" + f.engine
            if prev.category == Category.GENERIC_SECRET and f.category != Category.GENERIC_SECRET:
                prev.category = f.category
            if prev.key is None and f.key:
                prev.key = f.key
            prev.exact = prev.exact and f.exact
            continue
        seen[k] = f
    # Inexact findings are kept separately (their fingerprint is of the header only)
    return sorted(seen.values(), key=lambda f: (f.location.value, f.file, f.line, f.rule_id))
