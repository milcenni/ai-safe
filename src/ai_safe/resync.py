"""`ai-safe resync`: rebuild the AI workspace from the original repository, in place.

An AI session may still be open in the workspace, so nothing unverified may ever
appear there. The new workspace is built and verified in a private staging
directory next to the live one, then swapped in with ``os.rename`` only. The
workspace keeps its path and directory inode. Any failure leaves the old
workspace and the session state as they were (fail closed).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ai_safe.config import AISafeConfig
from ai_safe.credential_map import CredentialMap
from ai_safe.patch_manager import FileChange, collect_changes
from ai_safe.sanitizer import Sanitizer
from ai_safe.scanner import Scanner
from ai_safe.security import (
    MARKER_FILE,
    WORKSPACE_PREFIX,
    SecurityError,
    detect_ai_agent_env,
    ensure_private_dir,
    is_within,
    secure_mkdtemp,
    secure_remove_tree,
)
from ai_safe.verifier import VerificationReport, verify_workspace
from ai_safe.workspace import (
    IncompleteRollbackError,
    Session,
    SessionStore,
    replace_tree_contents,
    tree_hash,
    write_marker,
)

PENDING_REASON = "workspace has changes not integrated - run ai-safe integrate, or resync --discard"
STATE_ITEMS = ("manifest.json", "credential-map.json", "credential-secrets.enc", "snapshot")


@dataclass
class ResyncResult:
    ok: bool
    reason: str | None
    verification: VerificationReport | None


def pending_changes(session: Session) -> list[FileChange]:
    """Workspace changes since the snapshot, or ``[]`` when the workspace is exactly
    what the developer last integrated in full."""
    ws = session.workspace_path
    if session.integrated_tree_hash and tree_hash(ws) == session.integrated_tree_hash:
        return []
    return collect_changes(session.snapshot_dir, ws)


def _check_workspace(session: Session, store: SessionStore) -> Path:
    ws = session.workspace_path
    if ws.is_symlink() or not ws.is_dir() or not ws.name.startswith(WORKSPACE_PREFIX):
        raise SecurityError("the session workspace is missing or is not an ai-safe workspace")
    if is_within(ws, session.repo_path) or is_within(session.repo_path, ws):
        raise SecurityError("workspace overlaps the original repository")
    marker = ws / MARKER_FILE
    try:
        sid = json.loads(marker.read_text()).get("session_id") if marker.is_file() and not marker.is_symlink() else None
    except Exception:
        sid = None
    if sid != session.id:
        raise SecurityError("workspace marker does not match the session")
    if not is_within(session.state_path, store.sessions_dir):
        raise SecurityError("session state is outside the ai-safe state directory")
    return ws


class _StateKept(SecurityError):
    """Undoing the state swap failed; the old state is kept in ``stage/.old``."""


def _swap_state(live: Path, stage: Path) -> list[tuple[Path, Path]]:
    """Move the new state items from ``stage`` into ``live``; the old ones go to
    ``stage/.old``. Returns the performed renames so they can be undone."""
    old = ensure_private_dir(stage / ".old")
    done: list[tuple[Path, Path]] = []
    try:
        for name in STATE_ITEMS:
            if os.path.lexists(live / name):
                os.rename(live / name, old / name)
                done.append((live / name, old / name))
            if os.path.lexists(stage / name):
                os.rename(stage / name, live / name)
                done.append((stage / name, live / name))
    except BaseException as exc:
        _undo(done, old)
        if isinstance(exc, OSError):
            raise SecurityError("could not replace the session state; nothing was changed") from None
        raise
    return done


def _undo(done: list[tuple[Path, Path]], old: Path) -> None:
    """Reverse the renames in ``done``. If that fails, the old state stays in
    ``old`` (never shredded) and ``_StateKept`` names it."""
    try:
        for src, dst in reversed(done):
            os.rename(dst, src)
    except BaseException:
        raise _StateKept(
            f"resync failed and the old session state could not be restored; it is kept in {old}. "
            "The session is marked 'resyncing': open and integrate refuse it until it is repaired."
        ) from None


def resync(
    session: Session,
    cfg: AISafeConfig,
    store: SessionStore,
    scanner: Scanner,
    salt: bytes,
    *,
    discard: bool,
    passphrase: str | None,
) -> ResyncResult:
    agent = detect_ai_agent_env()
    if agent:
        raise SecurityError(
            f"resync must be run by the developer, not by an AI agent (detected ${agent}). "
            "Run `ai-safe resync` yourself in a normal terminal."
        )
    ws = _check_workspace(session, store)
    stage_state = store.sessions_dir / f"{session.id}.resync"
    if os.path.lexists(stage_state / ".old"):
        raise SecurityError(
            f"an earlier resync kept the old session state in {stage_state / '.old'}; "
            "inspect it, then remove that directory before resyncing again"
        )
    if pending_changes(session) and not discard:
        return ResyncResult(False, PENDING_REASON, None)

    scan = scanner.scan(session.repo_path)

    if os.path.lexists(stage_state):  # leftover of an interrupted resync
        secure_remove_tree(stage_state, shred=True)
    stage_ws: Path | None = None
    keep_state = False
    try:
        ensure_private_dir(stage_state)
        stage_ws = secure_mkdtemp(WORKSPACE_PREFIX, ws.parent)  # same filesystem as ws: rename only
        staging = Session(id=session.id, repo=session.repo, workspace=str(stage_ws),
                          state_dir=str(stage_state), created_at=session.created_at)
        write_marker(stage_ws, session.id)
        Sanitizer(cfg, scanner, salt).run(scan, staging, passphrase=passphrase)
        cmap = CredentialMap.load(stage_state)
        vr = verify_workspace(stage_ws, cfg, scanner, original_repo=session.repo_path, fingerprints=cmap.fingerprints())
        if not vr.passed:
            return ResyncResult(False, "verification failed", vr)

        # The AI may have kept working while we staged: re-check right before the swap.
        if not discard and pending_changes(session):
            return ResyncResult(False, PENDING_REASON, None)

        # Fail closed across crashes: while state and workspace are being swapped the
        # session is "resyncing" with no verified hash, so open/integrate refuse it.
        # The old values come back only after a complete rollback.
        prev = (session.status, session.verified_tree_hash)
        session.status, session.verified_tree_hash = "resyncing", None
        session.save()
        try:
            done = _swap_state(session.state_path, stage_state)
        except _StateKept:
            keep_state = True
            raise
        except BaseException:
            session.status, session.verified_tree_hash = prev
            session.save()
            raise
        try:
            replace_tree_contents(ws, stage_ws)
        except BaseException as exc:
            try:
                _undo(done, stage_state / ".old")
            except _StateKept:
                keep_state = True
                raise
            if not isinstance(exc, IncompleteRollbackError):
                session.status, session.verified_tree_hash = prev
                session.save()
            raise
        session.status = "verified"
        session.verified_tree_hash = tree_hash(ws)
        session.integrated_tree_hash = None
        session.history_only_secrets = staging.history_only_secrets
        session.save()
        return ResyncResult(True, None, vr)
    finally:
        if stage_ws is not None:
            secure_remove_tree(stage_ws)
        if not keep_state:
            secure_remove_tree(stage_state, shred=True)
