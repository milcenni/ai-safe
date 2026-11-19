"""ai-safe command line interface.

Exit codes: 0 = OK, 1 = security check failed / secrets found, 2 = invalid
configuration or usage, 3 = operational error (fail closed).
"""

from __future__ import annotations

import functools
import os
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from ai_safe import __version__
from ai_safe import git_history as gh
from ai_safe.config import CONFIG_FILENAME, DEFAULT_CONFIG_YAML, AISafeConfig, ConfigError, load_config
from ai_safe.credential_map import PASSPHRASE_ENV, CredentialMap
from ai_safe.integration import integrate as do_integrate
from ai_safe.redaction import PlaceholderRegistry
from ai_safe.reporting import console, render_issues, render_review, render_sanitize, render_scan, write_json
from ai_safe.sanitizer import Sanitizer, history_summary
from ai_safe.scanner import Scanner
from ai_safe.security import REDACTOR, SecurityError, detect_ai_agent_env, safe_display
from ai_safe.verifier import verify_workspace
from ai_safe.workspace import Session, SessionStore, install_skills, state_root

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3

app = typer.Typer(
    name="ai-safe",
    help="Keep real credentials and Git history away from AI coding agents.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
mapping_app = typer.Typer(help="Inspect the credential mapping (never shows values).", no_args_is_help=True)
skills_app = typer.Typer(help="Claude Code skills.", no_args_is_help=True)
app.add_typer(mapping_app, name="mapping")
app.add_typer(skills_app, name="skills")

ConfigOpt = Annotated[Optional[Path], typer.Option("--config", "-c", help="Path to ai-safe.yaml")]
SessionOpt = Annotated[Optional[str], typer.Option("--session", "-s", help="Session id (default: current workspace / latest for this repo)")]
PathArg = Annotated[Path, typer.Argument(help="Repository or project directory")]


def guarded(fn):
    """Map exceptions to exit codes with redacted messages (fail closed)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except typer.Exit:
            raise
        except ConfigError as exc:
            console(stderr=True).print(f"[red]config error:[/red] {exc}")
            raise typer.Exit(EXIT_USAGE)
        except (SecurityError, OSError, ValueError, UnicodeDecodeError) as exc:
            msg = REDACTOR.redact(str(exc))
            console(stderr=True).print(f"[red]error:[/red] {msg}")
            if os.environ.get("AI_SAFE_DEBUG"):
                raise
            raise typer.Exit(EXIT_ERROR)

    return wrapper


def _root(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.is_dir():
        raise SecurityError(f"not a directory: {path}")
    return gh.repo_root(path) if gh.is_git_repo(path) else path


def _setup(path: Path, config: Path | None) -> tuple[Path, AISafeConfig, SessionStore, bytes, Scanner]:
    root = _root(path)
    cfg = load_config(config, root)
    store = SessionStore(state_root(cfg))
    salt = store.repo_salt(root)
    return root, cfg, store, salt, Scanner(cfg, salt)


def _session_context(session_id: str | None, config: Path | None) -> tuple[Session, AISafeConfig, SessionStore, Scanner]:
    cwd = Path.cwd()
    # state root may come from config in the repo; resolve with defaults first
    store = SessionStore(state_root(load_config(config, None) if config else None))
    session = store.resolve(session_id, cwd)
    cfg = load_config(config, session.repo_path if session.repo_path.is_dir() else None)
    salt = store.repo_salt(session.repo_path)
    return session, cfg, store, Scanner(cfg, salt)


def _passphrase(cfg: AISafeConfig) -> str | None:
    if not cfg.security.store_secret_values:
        return None
    if os.environ.get(PASSPHRASE_ENV):
        return os.environ[PASSPHRASE_ENV]
    return typer.prompt("Passphrase for encrypted credential mapping", hide_input=True, confirmation_prompt=True)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
@guarded
def scan(
    path: PathArg = Path("."),
    config: ConfigOpt = None,
    no_history: Annotated[bool, typer.Option("--no-history", help="Skip Git history scan")] = False,
    report: Annotated[Optional[Path], typer.Option("--report", "-o", help="Write sanitized JSON report")] = None,
    gitleaks_report: Annotated[Optional[Path], typer.Option("--gitleaks-report", help="Merge an existing Gitleaks JSON report")] = None,
) -> None:
    """Detect secrets in tracked/untracked/ignored files, staged and unstaged changes and full Git history."""
    root, cfg, store, salt, scanner = _setup(path, config)
    c = console()
    result = scanner.scan(root, include_history=False if no_history else None, gitleaks_report=gitleaks_report)
    render_scan(result, c)
    if report:
        write_json(report, result.public())
        c.print(f"Report written to {report}")
    raise typer.Exit(EXIT_FAIL if result.findings else EXIT_OK)


# ---------------------------------------------------------------------------
# sanitize / verify / start
# ---------------------------------------------------------------------------


def _sanitize(root, cfg, store, salt, scanner, c, history_summary_flag: bool | None = None):
    result = scanner.scan(root)
    render_scan(result, c)
    if history_summary_flag is not None:
        cfg.sanitization.history_summary = history_summary_flag
    session = store.create(root, cfg)
    try:
        sres = Sanitizer(cfg, scanner, salt).run(result, session, passphrase=_passphrase(cfg))
    except BaseException:
        store.cleanup(session)
        raise
    write_json(session.reports_dir / "scan.json", result.public())
    render_sanitize(sres, c)
    return result, session, sres


def _verify(session: Session, cfg: AISafeConfig, scanner: Scanner, c) -> bool:
    cmap = CredentialMap.load(session.state_path)
    vr = verify_workspace(session.workspace_path, cfg, scanner, original_repo=session.repo_path, fingerprints=cmap.fingerprints())
    write_json(session.reports_dir / "verify.json", vr.public())
    render_issues("Verification", vr.issues, c, vr.passed)
    if vr.passed:
        session.status = "verified"
        session.verified_tree_hash = vr.tree_hash
    else:
        session.status = "failed"
    session.save()
    return vr.passed


@app.command()
@guarded
def sanitize(
    path: PathArg = Path("."),
    config: ConfigOpt = None,
    history_summary_flag: Annotated[Optional[bool], typer.Option("--history-summary/--no-history-summary", help="Add a sanitized Git history summary to the workspace")] = None,
) -> None:
    """Create an isolated, sanitized AI workspace (run `ai-safe verify` before giving it to AI)."""
    root, cfg, store, salt, scanner = _setup(path, config)
    c = console()
    _, session, _ = _sanitize(root, cfg, store, salt, scanner, c, history_summary_flag)
    c.print(f"\nSession: [bold]{session.id}[/bold]\nWorkspace: [bold]{session.workspace}[/bold]")
    c.print("Next: run [bold]ai-safe verify --session " + session.id + "[/bold] before giving the workspace to an AI agent.")


@app.command()
@guarded
def verify(
    session_id: SessionOpt = None,
    config: ConfigOpt = None,
    workspace: Annotated[Optional[Path], typer.Option("--workspace", "-w", help="Verify an arbitrary directory (no session)")] = None,
    report: Annotated[Optional[Path], typer.Option("--report", "-o")] = None,
) -> None:
    """Scan the entire AI workspace. Non-zero exit if anything unsafe remains."""
    c = console()
    if workspace is not None:
        ws = workspace.expanduser().resolve()
        cfg = load_config(config, None)
        store = SessionStore(state_root(cfg))
        scanner = Scanner(cfg, store.repo_salt(ws))
        vr = verify_workspace(ws, cfg, scanner)
        render_issues("Verification", vr.issues, c, vr.passed)
        if report:
            write_json(report, vr.public())
        raise typer.Exit(EXIT_OK if vr.passed else EXIT_FAIL)
    session, cfg, store, scanner = _session_context(session_id, config)
    ok = _verify(session, cfg, scanner, c)
    if report:
        write_json(report, json_load(session.reports_dir / "verify.json"))
    raise typer.Exit(EXIT_OK if ok else EXIT_FAIL)


def json_load(p: Path) -> dict:
    import json

    return json.loads(p.read_text())


@app.command()
@guarded
def start(
    path: PathArg = Path("."),
    config: ConfigOpt = None,
    launch: Annotated[bool, typer.Option("--launch", help="Launch the AI agent in the workspace (requires security.allow_ai_launch)")] = False,
    history_summary_flag: Annotated[Optional[bool], typer.Option("--history-summary/--no-history-summary")] = None,
) -> None:
    """Scan, sanitize and verify; then print how to start Claude Code in the safe workspace."""
    root, cfg, store, salt, scanner = _setup(path, config)
    c = console()
    if detect_ai_agent_env():
        c.print("[yellow]warning:[/yellow] ai-safe start appears to run inside an AI agent session. "
                "The agent running this command can already read the original repository.")
    scan_result, session, sres = _sanitize(root, cfg, store, salt, scanner, c, history_summary_flag)
    ok = _verify(session, cfg, scanner, c)
    if not ok:
        store.cleanup(session)
        c.print("[bold red]Verification failed - the workspace was securely removed (fail closed).[/bold red]")
        c.print("Fix the reported issues (or extend sanitization.exclude) and run `ai-safe start` again.")
        raise typer.Exit(EXIT_FAIL)

    hist = len({f.fingerprint for f in scan_result.history_findings})
    c.print()
    c.print(f"[bold green]AI-safe workspace ready[/bold green]  (session {session.id})")
    c.print(f"  Workspace : {session.workspace}")
    c.print(f"  Secrets   : {len({f.fingerprint for f in scan_result.findings})} unique detected, "
            f"{len(sres.credential_map.entries)} placeholder(s), {len(sres.excluded)} file(s) excluded")
    c.print(f"  History   : original .git NOT copied; {hist} credential(s) found in history" + (" - ROTATE THEM" if hist else ""))
    c.print("  Mapping   : stored outside the workspace (no values" + (", encrypted values kept" if cfg.security.store_secret_values else "") + ")")
    c.print()
    c.print("[bold]Launch Claude Code inside the sanitized workspace only:[/bold]")
    c.print(f"  cd {session.workspace} && claude")
    c.print("Recommended isolation (skills and settings are guidance, not a security boundary):")
    c.print("  - run the agent as a separate OS user or in a container that mounts ONLY the workspace, e.g.")
    c.print(f"    docker run --rm -it -v {session.workspace}:/workspace -w /workspace <image-with-claude> claude")
    c.print("  - do not use --add-dir with the original repository or ~/.local/state/ai-safe")
    c.print("When done:  ai-safe review   then (you, not the AI)  ai-safe integrate")

    if launch:
        if not cfg.security.allow_ai_launch:
            c.print("[red]--launch refused: security.allow_ai_launch is false[/red]")
            raise typer.Exit(EXIT_USAGE)
        env = {k: v for k, v in os.environ.items() if k in set(cfg.security.launch_env_allowlist)}
        env["AI_SAFE_AGENT"] = "1"
        subprocess.run(cfg.security.launch_command, cwd=session.workspace, env=env, check=False)


# ---------------------------------------------------------------------------
# review / integrate
# ---------------------------------------------------------------------------


@app.command()
@guarded
def review(
    session_id: SessionOpt = None,
    config: ConfigOpt = None,
    report: Annotated[Optional[Path], typer.Option("--report", "-o")] = None,
) -> None:
    """Review AI changes against the pristine snapshot. Non-zero exit on blocking issues."""
    from ai_safe.review import review_session

    session, cfg, store, scanner = _session_context(session_id, config)
    c = console()
    rr = review_session(session, cfg, scanner)
    data = rr.public()
    write_json(session.reports_dir / "review.json", data)
    if report:
        write_json(report, data)
    render_review(rr, c)
    raise typer.Exit(EXIT_OK if rr.passed else EXIT_FAIL)


@app.command()
@guarded
def integrate(
    session_id: SessionOpt = None,
    config: ConfigOpt = None,
    exclude: Annotated[Optional[list[str]], typer.Option("--exclude", "-x", help="Skip this path (repeatable)")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Review and build the patch only")] = False,
) -> None:
    """Apply reviewed AI changes to the original repository (patch-based, explicit approval, no commit/push)."""
    session, cfg, store, scanner = _session_context(session_id, config)
    c = console()

    def confirm(rr, patch: str) -> bool:
        render_review(rr, c)
        c.rule("Patch (credential lines hidden)")
        c.print(safe_display(patch), markup=False)
        c.rule()
        n = len(rr.plan)
        answer = typer.prompt(f"Type 'apply' to integrate {n} change(s) into {session.repo}", default="", show_default=False)
        return answer.strip() == "apply"

    res = do_integrate(session, cfg, scanner, confirm=confirm, exclude_paths=tuple(exclude or ()), dry_run=dry_run)
    if res.review is not None and res.aborted and res.reason == "review found blocking issues":
        render_review(res.review, c)
    if res.issues:
        render_issues("Final security scan", res.issues, c, False)
    if res.aborted:
        c.print(f"[yellow]Integration not applied:[/yellow] {res.reason}")
        if res.patch_path:
            c.print(f"Redacted patch record: {res.patch_path}")
        ok_reasons = {"dry run", "no integratable changes"}
        raise typer.Exit(EXIT_OK if res.reason in ok_reasons else EXIT_FAIL)
    write_json(session.reports_dir / "integration.json", {"applied": res.applied, "deleted": res.deleted, "patch": res.patch_path})
    c.print(f"[green]Applied {len(res.applied)} file(s), deleted {len(res.deleted)}.[/green]")
    c.print("Nothing was committed or pushed. Inspect with `git diff`, run your tests, then commit yourself.")


# ---------------------------------------------------------------------------
# housekeeping
# ---------------------------------------------------------------------------


@app.command()
@guarded
def cleanup(
    session_id: SessionOpt = None,
    all_sessions: Annotated[bool, typer.Option("--all", help="Remove every ai-safe session")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation")] = False,
    config: ConfigOpt = None,
) -> None:
    """Securely delete AI workspaces, snapshots and credential mappings."""
    c = console()
    store = SessionStore(state_root(load_config(config, None) if config else None))
    sessions = store.list() if all_sessions else [store.resolve(session_id, Path.cwd())]
    if not sessions:
        c.print("No sessions.")
        return
    for s in sessions:
        c.print(f"- {s.id}  workspace={s.workspace}")
    if not yes and not typer.confirm(f"Securely delete {len(sessions)} session(s)?", default=False):
        raise typer.Exit(EXIT_OK)
    for s in sessions:
        for removed in store.cleanup(s):
            c.print(f"removed {removed}")


@app.command()
@guarded
def sessions(config: ConfigOpt = None) -> None:
    """List ai-safe sessions."""
    from rich.table import Table

    store = SessionStore(state_root(load_config(config, None) if config else None))
    t = Table(title="ai-safe sessions")
    for col in ("Session", "Status", "Created", "Repository", "Workspace"):
        t.add_column(col, overflow="fold")
    for s in store.list():
        t.add_row(s.id, s.status, s.created_at, s.repo, s.workspace + ("" if Path(s.workspace).exists() else " (gone)"))
    console().print(t)


@app.command("history-summary")
@guarded
def history_summary_cmd(
    path: PathArg = Path("."),
    config: ConfigOpt = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    max_commits: Annotated[int, typer.Option("--max-commits")] = 200,
) -> None:
    """Print a sanitized Git history summary (no diffs, no authors, redacted subjects)."""
    root, cfg, store, salt, scanner = _setup(path, config)
    if not gh.is_git_repo(root):
        raise SecurityError("not a Git repository")
    result = scanner.scan(root)
    reg = PlaceholderRegistry(salt)
    for f in result.findings:
        if f.exact and f.secret:
            reg.register(f.secret, f.category, f.key)
    text = history_summary(root, scanner, reg, max_commits)
    if output:
        from ai_safe.security import write_private_file

        write_private_file(output, text, mode=0o644)
        console().print(f"written to {output}")
    else:
        console().print(text, markup=False)


@app.command()
@guarded
def init(path: PathArg = Path("."), force: Annotated[bool, typer.Option("--force")] = False) -> None:
    """Write a default ai-safe.yaml."""
    target = path.resolve() / CONFIG_FILENAME
    if target.exists() and not force:
        raise SecurityError(f"{CONFIG_FILENAME} already exists (use --force)")
    target.write_text(DEFAULT_CONFIG_YAML)
    load_config(target)
    console().print(f"wrote {target}")


@app.command()
def version() -> None:
    """Show version information."""
    from ai_safe.gitleaks import Gitleaks, find_gitleaks

    exe = find_gitleaks(None)
    gl = Gitleaks(exe).version() if exe else "not found"
    console().print(f"ai-safe {__version__}  (gitleaks: {gl})")


@mapping_app.command("show")
@guarded
def mapping_show(
    session_id: SessionOpt = None,
    config: ConfigOpt = None,
    env_template: Annotated[bool, typer.Option("--env-template", help="Print NAME= lines for your secret manager")] = False,
) -> None:
    """Show placeholders, categories and files. Secret values are never displayed."""
    from rich.table import Table

    session, cfg, store, scanner = _session_context(session_id, config)
    cmap = CredentialMap.load(session.state_path)
    c = console()
    if env_template:
        c.print(cmap.env_template(), markup=False)
        return
    t = Table(title=f"Credential mapping - session {session.id}")
    for col in ("Placeholder", "Category", "Fingerprint", "Files"):
        t.add_column(col, overflow="fold")
    for e in cmap.entries:
        t.add_row(e.placeholder, e.category, e.fingerprint[:12], ", ".join(e.files) or "(history only)")
    c.print(t)
    c.print(f"Encrypted values stored: {'yes' if cmap.encrypted_values else 'no'}")


@skills_app.command("install")
@guarded
def skills_install(dest: Annotated[Path, typer.Argument(help="Project directory")] = Path(".")) -> None:
    """Install the ai-safe Claude Code skills into DEST/.claude/skills/."""
    for p in install_skills(dest.resolve()):
        console().print(f"wrote {p}")


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
