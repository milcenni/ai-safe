"""Terminal (Rich) and JSON reporting.

All terminal output goes through :class:`~ai_safe.security.RedactingStream`
and no renderer ever receives a secret value; reports contain fingerprints,
locations and categories only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ai_safe.models import Location, Severity
from rich.markup import escape

from ai_safe.security import REDACTOR, RedactingStream, safe_display, write_private_file

_SEV_STYLE = {
    Severity.INFO: "dim",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
    Severity.CRITICAL: "bold red",
}


def _u(text: str) -> str:
    """Untrusted text (paths, messages) -> safe for Rich markup and terminals."""
    return escape(safe_display(str(text)))


def console(stderr: bool = False) -> Console:
    stream = sys.stderr if stderr else sys.stdout
    return Console(file=RedactingStream(stream, REDACTOR), highlight=False, soft_wrap=True)


def write_json(path: Path, data: dict) -> Path:
    text = REDACTOR.redact(json.dumps(data, indent=2, default=str))
    write_private_file(Path(path), text)
    return Path(path)


def render_scan(result, c: Console, max_rows: int = 200) -> None:
    pub = result.public()
    s = pub["summary"]
    c.print(Panel.fit(
        f"Root: {result.root}\nEngines: {', '.join(result.engines)}\n"
        f"Files scanned: {result.files_scanned}   History scanned: {'yes' if result.history_scanned else 'no'}"
        f" ({result.history_commits} commits)\n"
        f"Findings: {s['total']}   Unique secrets: {s['unique_secrets']}",
        title="ai-safe scan", border_style="cyan",
    ))
    if not result.findings:
        c.print("[green]No secrets detected.[/green] (Pattern matching cannot prove absence - see README limitations.)")
        return
    t = Table(title="Findings (values never shown)", show_lines=False)
    for col in ("Location", "Category", "Rule", "File:Line", "Commit", "Engine", "Fingerprint"):
        t.add_column(col, overflow="fold")
    for f in result.findings[:max_rows]:
        t.add_row(f.location.value, f.category.value, _u(f.rule_id), _u(f"{f.file}:{f.line}"), f.commit or "",
                  f.engine, (f.fingerprint or "")[:12] + ("" if f.exact else " (unbounded)"))
    c.print(t)
    if len(result.findings) > max_rows:
        c.print(f"... {len(result.findings) - max_rows} more (see JSON report)")
    cat = Table(title="By category")
    cat.add_column("Category")
    cat.add_column("Count", justify="right")
    for k, v in sorted(s["by_category"].items()):
        cat.add_row(k, str(v))
    loc = Table(title="By location")
    loc.add_column("Location")
    loc.add_column("Count", justify="right")
    for k, v in sorted(s["by_location"].items()):
        loc.add_row(k, str(v))
    c.print(cat)
    c.print(loc)
    hist = [f for f in result.findings if f.location == Location.HISTORY]
    if hist:
        c.print(Panel(
            f"{len({f.fingerprint for f in hist})} credential(s) were found in Git history "
            f"({s['history_only_secrets']} no longer present in the working tree).\n"
            "Any credential that was ever committed must be considered exposed and ROTATED.\n"
            "Sanitization protects the AI workspace only; it does not undo prior exposure.\n"
            "ai-safe never rewrites Git history.",
            title="Git history exposure", border_style="red",
        ))


def render_sanitize(res, c: Console) -> None:
    t = Table(title="Sanitization manifest")
    t.add_column("Action")
    t.add_column("Count", justify="right")
    t.add_row("sanitized (placeholders inserted)", str(len(res.sanitized)))
    t.add_row("copied unchanged", str(len(res.copied)))
    t.add_row("excluded", str(len(res.excluded)))
    t.add_row("placeholders", str(len(res.credential_map.entries)))
    c.print(t)
    if res.excluded:
        ex = Table(title="Excluded from AI workspace")
        ex.add_column("Path", overflow="fold")
        ex.add_column("Reason", overflow="fold")
        for e in res.excluded[:100]:
            ex.add_row(_u(e.path), _u(e.reason or ""))
        c.print(ex)
        if len(res.excluded) > 100:
            c.print(f"... {len(res.excluded) - 100} more in manifest.json")
    for w in res.warnings:
        c.print(f"[yellow]warning:[/yellow] {w}")


def render_issues(title: str, issues, c: Console, passed: bool) -> None:
    if issues:
        t = Table(title=title)
        for col in ("Severity", "Code", "Path", "Line", "Message"):
            t.add_column(col, overflow="fold")
        for i in sorted(issues, key=lambda i: (-i.severity.rank, i.path)):
            t.add_row(f"[{_SEV_STYLE[i.severity]}]{i.severity.value}[/]", i.code, _u(i.path), str(i.line or ""), _u(i.message))
        c.print(t)
    status = "[bold green]PASSED[/bold green]" if passed else "[bold red]FAILED[/bold red]"
    c.print(f"{title}: {status}")


def render_review(report, c: Console) -> None:
    t = Table(title="AI changes")
    t.add_column("Change")
    t.add_column("Path", overflow="fold")
    for ch in report.changes:
        t.add_row(ch.kind, _u(ch.path))
    if report.changes:
        c.print(t)
    else:
        c.print("No changes in the AI workspace.")
    for s in report.skipped:
        c.print(f"[dim]skipped:[/dim] {_u(s)}")
    render_issues("Review", report.issues, c, report.passed)
    if report.passed and report.plan:
        c.print(f"{len(report.plan)} change(s) can be integrated with `ai-safe integrate` (run by the developer).")
