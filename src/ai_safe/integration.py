"""Controlled, patch-based integration of reviewed AI changes.

Order of operations (any failure aborts before the original repo is touched):

1. refuse to run from inside an AI agent session or from the AI workspace;
2. run the full review; abort on any blocking issue;
3. validate every target path (traversal, symlinked components, Git metadata,
   excluded/sensitive files, original unchanged since sanitization);
4. stage the resulting files in a private temp dir and run the final
   Gitleaks + builtin scan; abort if any credential that did not already exist
   in the original file appears;
5. show a redacted patch and require explicit confirmation;
6. apply atomically (temp file + rename), preserving original file modes;
7. never commit, never push, never restore credentials into AI lines.
"""

from __future__ import annotations

import datetime as _dt
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ai_safe.classifier import is_security_tool_file, sensitive_match
from ai_safe.config import AISafeConfig
from ai_safe.credential_map import CredentialMap
from ai_safe.models import Issue, Location, Severity
from ai_safe.patch_manager import unified_diff_masked
from ai_safe.review import PlannedChange, ReviewReport, repo_salt, review_session
from ai_safe.scanner import Scanner
from ai_safe.security import (
    SecurityError,
    atomic_write,
    detect_ai_agent_env,
    hmac_fingerprint,
    is_git_metadata_path,
    is_within,
    keyed_digest,
    safe_join,
    secure_mkdtemp,
    secure_remove_tree,
    write_private_file,
)
from ai_safe.workspace import Session, tree_hash


@dataclass
class IntegrationResult:
    applied: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    aborted: bool = False
    reason: str | None = None
    review: ReviewReport | None = None
    patch_path: str | None = None
    issues: list[Issue] = field(default_factory=list)


def guard_human_context(session: Session, cwd: Path) -> None:
    agent = detect_ai_agent_env()
    if agent:
        raise SecurityError(
            f"integration must be run by the developer, not by an AI agent (detected ${agent}). "
            "Run `ai-safe integrate` yourself in a normal terminal."
        )
    if is_within(cwd, session.workspace_path):
        raise SecurityError("integration cannot be run from inside the AI workspace")
    if session.status == "resyncing":
        raise SecurityError("an ai-safe resync of this workspace did not finish; run `ai-safe resync` first (fail closed)")
    if not session.verified_tree_hash:
        raise SecurityError("this workspace never passed `ai-safe verify`; integration refused (fail closed)")


def build_patch(plan: list[PlannedChange], repo: Path) -> str:
    parts = []
    for p in plan:
        if p.kind == "delete":
            parts.append(f"deleted file: {p.path}\n")
        elif p.is_new:
            parts.append(unified_diff_masked(p.path, "", p.content.decode("utf-8", "replace"), set()) or f"new file: {p.path}\n")
        else:
            parts.append(unified_diff_masked(p.path, p.original_text or "", p.content.decode("utf-8", "replace"), p.credential_lines))
    return "".join(parts)


def _validate_targets(plan: list[PlannedChange], repo: Path, cfg: AISafeConfig) -> None:
    excludes = cfg.sanitization.all_excludes()
    for p in plan:
        if is_git_metadata_path(p.path):
            raise SecurityError(f"refusing to write Git metadata: {p.path}")
        if sensitive_match(p.path, excludes) or is_security_tool_file(p.path):
            raise SecurityError(f"refusing to modify a sensitive file: {p.path}")
        target = safe_join(repo, p.path)  # traversal + symlinked components
        if target.is_symlink():
            raise SecurityError(f"refusing to write through a symlink: {p.path}")
        if p.kind == "write" and p.is_new and os.path.lexists(target):
            raise SecurityError(f"refusing to overwrite existing file: {p.path}")


def _final_scan(plan: list[PlannedChange], scanner: Scanner, original_fps: set[str]) -> list[Issue]:
    """Scan the post-integration content of every written file. Credentials
    already present in the original (known fingerprints) are expected; any
    other detection aborts integration."""
    issues: list[Issue] = []
    writes = [p for p in plan if p.kind == "write"]
    if not writes:
        return issues
    tmp = secure_mkdtemp("ai-safe-final-")
    try:
        for p in writes:
            dst = tmp / p.path
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(p.content)
        for p in writes:
            text = p.content.decode("utf-8", "replace")
            pre = {hmac_fingerprint(m.secret, scanner.salt) for m in scanner.detector.scan_text(p.original_text or "", p.path)}
            for m in scanner.detector.scan_text(text, p.path):
                fp = hmac_fingerprint(m.secret, scanner.salt)
                if fp in original_fps or fp in pre:
                    continue
                issues.append(Issue(Severity.ERROR, "final-scan", p.path, f"new credential detected in integrated content ({m.rule_id})", m.line))
        if scanner.gitleaks:
            for rec in scanner.gitleaks.scan_dir(tmp):
                f = scanner.from_gitleaks(rec, Location.WORKSPACE)
                if f is None or f.fingerprint in original_fps:
                    continue
                orig = next((p.original_text for p in writes if p.path == f.file), None) or ""
                if f.secret and f.secret in orig:
                    continue
                issues.append(Issue(Severity.ERROR, "final-scan-gitleaks", f.file, f"gitleaks: new credential in integrated content ({f.rule_id})", f.line))
    finally:
        secure_remove_tree(tmp, shred=True)
    return issues


def integrate(
    session: Session,
    cfg: AISafeConfig,
    scanner: Scanner,
    *,
    confirm: Callable[[ReviewReport, str], bool],
    exclude_paths: tuple[str, ...] = (),
    dry_run: bool = False,
    cwd: Path | None = None,
) -> IntegrationResult:
    guard_human_context(session, Path(cwd or os.getcwd()))
    repo = session.repo_path
    result = IntegrationResult()
    # Hash before review: integrated_tree_hash must describe the reviewed workspace, not later AI edits.
    reviewed_hash = tree_hash(session.workspace_path)
    review = review_session(session, cfg, scanner, exclude_paths=exclude_paths)
    result.review = review
    if not review.passed:
        result.aborted, result.reason = True, "review found blocking issues"
        return result
    plan = review.plan
    if not plan:
        result.aborted, result.reason = True, "no integratable changes"
        return result

    _validate_targets(plan, repo, cfg)
    original_fps = set(CredentialMap.load(session.state_path).fingerprints())
    issues = _final_scan(plan, scanner, original_fps)
    if issues:
        result.issues = issues
        result.aborted, result.reason = True, "final security scan failed"
        return result

    patch = build_patch(plan, repo)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    patch_path = session.patches_dir / f"{stamp}.patch"
    write_private_file(patch_path, patch)
    result.patch_path = str(patch_path)

    if dry_run:
        result.aborted, result.reason = True, "dry run"
        return result
    if not confirm(review, patch):
        result.aborted, result.reason = True, "not approved by developer"
        return result

    # Re-validate right before writing (TOCTOU) and apply atomically.
    _validate_targets(plan, repo, cfg)
    salt = repo_salt(session)
    for p in plan:
        target = safe_join(repo, p.path)
        if p.kind == "delete":
            if target.is_file() and not target.is_symlink():
                if keyed_digest(target.read_bytes(), salt) != p.original_digest:
                    raise SecurityError(f"original file changed during integration: {p.path}")
                target.unlink()
                result.deleted.append(p.path)
            continue
        if not p.is_new:
            current = target.read_bytes().decode("utf-8", "replace")
            if current != p.original_text:
                raise SecurityError(f"original file changed during integration: {p.path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        safe_join(repo, p.path)
        atomic_write(target, p.content, p.mode or 0o644)
        result.applied.append(p.path)
    session.status = "integrated"
    # Only a full integration of an unchanged workspace means "workspace == what the developer
    # accepted" (resync relies on it). Any edit during review/approval clears it.
    unchanged = tree_hash(session.workspace_path) == reviewed_hash
    # A change review left out (``manual`` binary/mode-only, Git metadata, already-absent deletion, ...)
    # is not integrated, so resync without --discard would silently drop it.
    full = not exclude_paths and not review.left_out()
    session.integrated_tree_hash = reviewed_hash if unchanged and full else None
    session.save()
    return result
