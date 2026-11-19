"""Review of AI-generated changes.

Compares the workspace against the pristine snapshot (stored outside the
workspace so the AI cannot tamper with the baseline) and reports:

* tampering with the workspace marker / security tooling configuration
* new or modified sensitive files (``.env``, keys, credential stores)
* symlinks, hard links, special files, unsafe path names, Git metadata, binaries
* hardcoded credentials introduced by the AI (builtin + Gitleaks + known
  original values via keyed fingerprints)
* placeholder misuse: placeholders copied into new lines, unknown
  placeholders, placeholders replaced with literal values
* hidden terminal-control / bidi characters (display spoofing, Trojan Source)
* weakened ignore rules (``.gitignore``) and new files in paths the original
  repository ignores (they would be invisible to ``git status``)
* sensitive configuration changes (CI, build, Docker, hooks) for human review
* integration conflicts against the original repository

Workspace content is read exactly once, race-free (see
:func:`ai_safe.security.walk_nofollow`); everything downstream - scanning,
planning and the bytes that integration writes - uses that captured copy.
Review never executes anything from the workspace.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ai_safe import git_history as gh
from ai_safe.classifier import is_security_tool_file, is_sensitive_config, match_exclude
from ai_safe.config import AISafeConfig
from ai_safe.credential_map import CredentialMap
from ai_safe.models import Issue, Location, Severity, is_blocking
from ai_safe.patch_manager import FileChange, collect_changes, compute_hunks, map_to_original
from ai_safe.scanner import Scanner
from ai_safe.security import (
    GIT_SAFE_CONFIG,
    HIDDEN_CHARS_RE,
    MARKER_FILE,
    PLACEHOLDER_NAME_RE,
    SecurityError,
    is_binary,
    is_git_metadata_path,
    is_placeholder_value,
    keyed_digest,
    run_command,
    safe_env,
    safe_relpath,
    secure_mkdtemp,
    secure_remove_tree,
)
from ai_safe.verifier import known_secret_hits
from ai_safe.workspace import Session, SessionStore, generated_paths

_ASSIGN_PLACEHOLDER = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)[\"']?\s*(?::=|=>|=|:)\s*[\"'`]?\$\{(?P<name>AI_SAFE_SECRET_[A-Z0-9_]+)\}")
_ASSIGN_LITERAL = r"{key}[\"']?\s*(?::=|=>|=|:)\s*(?P<q>[\"'`])(?P<value>[^\"'`\n]+)(?P=q)"
_IGNORE_FILES = {".gitignore", ".dockerignore"}


@dataclass
class PlannedChange:
    path: str
    kind: str  # write | delete
    content: bytes | None = None
    mode: int | None = None
    is_new: bool = False
    original_text: str | None = None
    credential_lines: set[int] = field(default_factory=set)
    original_digest: str | None = None


@dataclass
class ReviewReport:
    session_id: str
    changes: list[FileChange] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # tool metadata, not integrated
    plan: list[PlannedChange] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not is_blocking(self.issues)

    def add(self, severity: Severity, code: str, path: str, message: str, line: int | None = None) -> None:
        self.issues.append(Issue(severity, code, path, message, line))

    def public(self) -> dict:
        return {
            "session_id": self.session_id,
            "passed": self.passed,
            "changes": [{"path": c.path, "kind": c.kind} for c in self.changes],
            "integratable": [{"path": p.path, "action": p.kind} for p in self.plan],
            "skipped": self.skipped,
            "issues": [i.public() for i in sorted(self.issues, key=lambda i: (-i.severity.rank, i.path))],
        }


def _is_tool_metadata(path: str) -> bool:
    return path in generated_paths() or path.startswith(".claude/")


def repo_salt(session: Session) -> bytes:
    return SessionStore(session.state_path.parent.parent).repo_salt(session.repo_path)


def ignored_in_original(repo: Path, paths: list[str], skip_dirs: list[str]) -> set[str]:
    """Paths that the ORIGINAL repository ignores (or that live in tool
    directories such as .venv/node_modules). New files there would be
    invisible to ``git status`` / ``git diff``."""
    out = {p for p in paths if any(part in skip_dirs for part in PurePosixPath(p).parts[:-1])}
    if not paths or not gh.is_git_repo(repo):
        return out
    proc = run_command(
        ["git", *GIT_SAFE_CONFIG, "check-ignore", "-z", "--stdin"],
        cwd=repo, env=safe_env(), check=False, input_bytes=b"\x00".join(p.encode() for p in paths) + b"\x00",
    )
    if proc.returncode not in (0, 1):
        raise SecurityError("git check-ignore failed")
    out |= {p.decode("utf-8", "surrogateescape") for p in proc.stdout.split(b"\x00") if p}
    return out


def review_session(session: Session, cfg: AISafeConfig, scanner: Scanner, *, exclude_paths: tuple[str, ...] = ()) -> ReviewReport:
    ws = session.workspace_path
    snap = session.snapshot_dir
    repo = session.repo_path
    report = ReviewReport(session_id=session.id)
    if not snap.is_dir():
        raise SecurityError("session snapshot missing - cannot review")
    if not ws.is_dir():
        raise SecurityError("workspace missing - nothing to review")

    manifest = session.load_manifest()
    manifest_files = {f["path"]: f for f in manifest.get("files", [])}
    cmap = CredentialMap.load(session.state_path)
    known_names = cmap.names()
    fingerprints = cmap.fingerprints()
    excludes = cfg.sanitization.all_excludes()
    salt = repo_salt(session)
    changes = collect_changes(snap, ws)
    report.changes = changes
    gitleaks_inputs: list[tuple[str, bytes]] = []

    added_paths = [c.path for c in changes if c.kind == "added"]
    try:
        safe_added = [p for p in added_paths if _safe(p)]
        ignored = ignored_in_original(repo, safe_added, cfg.scanner.ignored_skip_dirs)
    except SecurityError:
        ignored = set(added_paths)

    for ch in changes:
        path = ch.path
        if path == MARKER_FILE:
            report.add(Severity.ERROR, "marker-tampered", path, "workspace marker was modified or deleted")
            continue
        if any(path == e or path.startswith(e.rstrip("/") + "/") for e in exclude_paths):
            report.skipped.append(f"{path} (excluded by --exclude)")
            continue
        try:
            safe_relpath(path)
        except SecurityError as exc:
            report.add(Severity.ERROR, "unsafe-path", repr(path)[1:-1], f"unsafe path name: {exc}")
            continue
        if HIDDEN_CHARS_RE.search(path):
            report.add(Severity.ERROR, "unsafe-path", repr(path)[1:-1], "path contains hidden/bidi characters")
            continue
        if is_git_metadata_path(path):
            report.skipped.append(f"{path} (Git metadata created in workspace - never integrated)")
            if not any(i.code == "nested-git" for i in report.issues):
                report.add(Severity.WARNING, "nested-git", path.split("/.git")[0] or ".git", "AI created Git metadata in the workspace; it will not be integrated")
            continue
        if _is_tool_metadata(path):
            report.skipped.append(f"{path} (ai-safe / Claude Code metadata - not integrated)")
            continue
        if is_security_tool_file(path):
            report.add(Severity.ERROR, "security-config", path, "change to security tooling configuration is not allowed")
            continue
        pat = match_exclude(path, excludes)
        if pat:
            report.add(Severity.ERROR, "sensitive-file", path, f"AI attempted to {ch.kind.replace('_', ' ')} a sensitive/excluded file (matches {pat!r})")
            continue
        if ch.new and ch.new.kind == "symlink":
            report.add(Severity.ERROR, "symlink", path, "AI created a symlink - symlinks are never integrated")
            continue
        if ch.new and ch.new.kind == "special":
            report.add(Severity.ERROR, "special-file", path, "special or unreadable file")
            continue
        if ch.kind == "type_changed":
            report.add(Severity.ERROR, "type-changed", path, "file type changed")
            continue
        if ch.new and ch.new.nlink > 1:
            report.add(Severity.ERROR, "hard-link", path, "hard-linked file (may alias a file outside the workspace)")
            continue
        if ch.kind == "added" and path in ignored:
            report.add(Severity.ERROR, "ignored-path", path,
                       "new file in a path the original repository ignores - it would be invisible to git status/diff")
            continue
        if is_sensitive_config(path) or PurePosixPath(path).name in _IGNORE_FILES:
            report.add(Severity.WARNING, "sensitive-config", path, "sensitive configuration/build/CI file changed - review carefully before integrating")

        if ch.kind == "deleted":
            _review_deletion(report, ch, manifest_files, cfg, repo, salt)
            continue

        new_bytes = ch.new.data if ch.new else None
        if new_bytes is None:
            report.add(Severity.ERROR, "unreadable", path, "file could not be read safely")
            continue
        if ch.new.size > cfg.scanner.max_file_size_kb * 1024:
            report.add(Severity.ERROR, "too-large", path, "file too large to verify")
            continue
        new_text: str | None = None
        if is_binary(new_bytes):
            if Path(path).suffix.lower() in cfg.sanitization.allowed_binary_extensions:
                report.add(Severity.WARNING, "binary", path, "binary file changed - review manually")
            else:
                report.add(Severity.ERROR, "unexpected-binary", path, "unexpected binary file created/modified by AI")
                continue
            text_for_scan = new_bytes.decode("latin-1")
        else:
            new_text = new_bytes.decode("utf-8")
            text_for_scan = new_text
        if ch.new.mode & 0o111 and (ch.old is None or not ch.old.mode & 0o111):
            report.add(Severity.WARNING, "executable", path, "new executable file - review before running anything")

        blocked = _scan_content(report, scanner, path, text_for_scan, fingerprints, salt)
        gitleaks_inputs.append((path, new_bytes))

        if new_text is not None:
            old_text = ""
            if ch.old is not None and ch.old.data is not None and not is_binary(ch.old.data):
                old_text = ch.old.data.decode("utf-8")
            blocked |= _placeholder_checks(report, path, old_text, new_text, known_names)
            blocked |= _hidden_char_checks(report, path, old_text, new_text)
            if PurePosixPath(path).name == ".gitignore":
                blocked |= _ignore_rule_checks(report, path, old_text, new_text)
        if blocked:
            continue
        if ch.kind == "added":
            if path.startswith("."):
                report.add(Severity.INFO, "hidden-file", path, "new hidden file")
            _plan_added(report, path, new_bytes, ch, repo)
        elif ch.kind in ("modified", "mode_changed"):
            _plan_modified(report, path, new_bytes, new_text, ch, session, manifest_files, repo, salt)

    if scanner.gitleaks and gitleaks_inputs:
        _gitleaks_on_changes(report, scanner, gitleaks_inputs)
    if not report.passed:
        report.plan = []
    return report


def _safe(path: str) -> bool:
    try:
        safe_relpath(path)
        return True
    except SecurityError:
        return False


def _scan_content(report, scanner: Scanner, path: str, text: str, fingerprints, salt: bytes) -> bool:
    blocked = False
    for m in scanner.detector.scan_text(text, path):
        if is_placeholder_value(m.secret):
            continue
        report.add(Severity.ERROR, "hardcoded-credential", path, f"hardcoded credential introduced ({m.rule_id}, {m.category.value})", m.line)
        blocked = True
    for name in sorted(known_secret_hits(text, fingerprints, salt)):
        report.add(Severity.CRITICAL, "known-secret", path, f"original credential value for {name} appears in AI output")
        blocked = True
    return blocked


def _placeholder_checks(report: ReviewReport, path: str, old_text: str, new_text: str, known_names: set[str]) -> bool:
    blocked = False
    for name in sorted(set(PLACEHOLDER_NAME_RE.findall(new_text)) - known_names):
        report.add(Severity.ERROR, "unknown-placeholder", path, f"unknown placeholder {name} (fabricated or altered)")
        blocked = True
    for h in compute_hunks(old_text, new_text):
        removed = "".join(h.old_lines)
        added = "".join(h.new_lines)
        line_no = h.i1 + 1
        for m in _ASSIGN_PLACEHOLDER.finditer(removed):
            key = re.escape(m.group("key"))
            lit = re.search(_ASSIGN_LITERAL.format(key=key), added)
            if lit and not is_placeholder_value(lit.group("value")) and "AI_SAFE_SECRET_" not in lit.group("value"):
                report.add(Severity.ERROR, "placeholder-replaced", path,
                           f"placeholder {m.group('name')} replaced with a literal value", line_no)
                blocked = True
        if PLACEHOLDER_NAME_RE.search(added):
            report.add(Severity.ERROR, "placeholder-in-new-code", path,
                       "AI-written line contains an AI_SAFE_SECRET placeholder; it would be integrated literally. "
                       "Use an environment variable / secret manager lookup instead", line_no)
            blocked = True
    return blocked


def _hidden_char_checks(report: ReviewReport, path: str, old_text: str, new_text: str) -> bool:
    for h in compute_hunks(old_text, new_text):
        for k, line in enumerate(h.new_lines):
            if HIDDEN_CHARS_RE.search(line):
                report.add(Severity.ERROR, "hidden-characters", path,
                           "AI-written line contains terminal control or bidi characters (display spoofing / Trojan Source)",
                           h.i1 + k + 1)
                return True
    return False


def _ignore_rule_checks(report: ReviewReport, path: str, old_text: str, new_text: str) -> bool:
    def rules(t: str) -> set[str]:
        return {ln.strip() for ln in t.splitlines() if ln.strip() and not ln.strip().startswith("#")}

    old_rules, new_rules = rules(old_text), rules(new_text)
    removed = old_rules - new_rules
    negations = {r for r in new_rules - old_rules if r.startswith("!")}
    if removed or negations:
        report.add(Severity.ERROR, "ignore-weakened", path,
                   f"AI removed {len(removed)} ignore rule(s) / added {len(negations)} negation(s); this could expose "
                   "secrets to git add - apply manually if intended")
        return True
    return False


def _review_deletion(report: ReviewReport, ch: FileChange, manifest_files: dict, cfg: AISafeConfig, repo: Path, salt: bytes) -> None:
    entry = manifest_files.get(ch.path)
    if not cfg.integration.allow_deletions:
        report.add(Severity.ERROR, "deletion", ch.path, "file deletion not allowed (integration.allow_deletions=false)")
        return
    if PurePosixPath(ch.path).name == ".gitignore":
        report.add(Severity.ERROR, "ignore-weakened", ch.path, "AI deleted an ignore file - apply manually if intended")
        return
    target = repo / ch.path
    if not target.is_file() or target.is_symlink():
        report.skipped.append(f"{ch.path} (already absent from the original)")
        return
    digest = keyed_digest(target.read_bytes(), salt)
    if entry is None or entry.get("original_digest") != digest:
        report.add(Severity.ERROR, "original-changed", ch.path, "original file changed since the workspace was created - not deleting")
        return
    if entry.get("action") == "sanitized":
        report.add(Severity.WARNING, "credential-file-deleted", ch.path, "AI deleted a file that contains original credentials - review carefully")
    report.plan.append(PlannedChange(ch.path, "delete", original_digest=digest))


def _plan_added(report: ReviewReport, path: str, data: bytes, ch: FileChange, repo: Path) -> None:
    target = repo / path
    if target.exists() or target.is_symlink():
        report.add(Severity.ERROR, "would-overwrite", path,
                   "new file would overwrite an existing original file that was not shared with the AI (excluded or ignored)")
        return
    mode = 0o755 if (ch.new and ch.new.mode & 0o100) else 0o644
    report.plan.append(PlannedChange(path, "write", data, mode, is_new=True))


def _plan_modified(report: ReviewReport, path: str, data: bytes, new_text: str | None, ch: FileChange,
                   session: Session, manifest_files: dict, repo: Path, salt: bytes) -> None:
    entry = manifest_files.get(path)
    target = repo / path
    if not target.is_file() or target.is_symlink():
        report.add(Severity.ERROR, "original-missing", path, "original file is missing or not a regular file")
        return
    orig_bytes = target.read_bytes()
    digest = keyed_digest(orig_bytes, salt)
    if entry is None or entry.get("original_digest") != digest:
        report.add(Severity.ERROR, "original-changed", path, "original file changed since the workspace was created - re-run ai-safe start")
        return
    mode = stat.S_IMODE(target.stat().st_mode)
    if ch.kind == "mode_changed" or new_text is None:
        report.add(Severity.WARNING, "manual", path, "binary or mode-only change is not integrated automatically")
        return
    snap_text = ch.old.data.decode("utf-8") if ch.old and ch.old.data is not None else ""
    mapped = map_to_original(snap_text, new_text, orig_bytes.decode("utf-8"), path)
    for line, msg in mapped.conflicts:
        report.add(Severity.ERROR, "conflict", path, msg, line)
    for line, msg in mapped.warnings:
        report.add(Severity.WARNING, "credential-removed", path, msg, line)
    if mapped.text is None:
        return
    report.plan.append(PlannedChange(path, "write", mapped.text.encode("utf-8"), mode, False,
                                     orig_bytes.decode("utf-8"), mapped.credential_lines_original, digest))


def _gitleaks_on_changes(report: ReviewReport, scanner: Scanner, items: list[tuple[str, bytes]]) -> None:
    tmp = secure_mkdtemp("ai-safe-review-")
    try:
        for path, data in items:
            p = tmp / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        for rec in scanner.gitleaks.scan_dir(tmp):
            f = scanner.from_gitleaks(rec, Location.WORKSPACE)
            if f is None:
                continue
            report.add(Severity.ERROR, "gitleaks", f.file, f"gitleaks: credential in AI change ({f.rule_id}, {f.category.value})", f.line)
            report.plan = [p for p in report.plan if p.path != f.file]
    finally:
        secure_remove_tree(tmp, shred=True)
