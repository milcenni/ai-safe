"""Gitleaks integration.

Gitleaks is used as a *detector*. Hardening applied to every invocation:

* An explicit config (``[extend] useDefault = true``) is always passed so a
  ``.gitleaks.toml`` planted in the scanned directory cannot weaken detection.
* ``--gitleaks-ignore-path`` points at an empty private directory so a planted
  ``.gitleaksignore`` cannot suppress findings.
* ``--ignore-gitleaks-allow`` disables inline ``gitleaks:allow`` comments.
* The JSON report (which contains raw secrets) is written to a private 0700
  temporary directory, parsed in memory and shredded immediately.
* ``--exit-code 0`` + report parsing distinguishes "leaks found" from failure.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from ai_safe.security import CommandError, SecurityError, run_command, safe_env, secure_mkdtemp, secure_remove_tree

GITLEAKS_ENV = "AI_SAFE_GITLEAKS"

_CONFIG_TOML = """title = "ai-safe"

[extend]
useDefault = true
"""


class GitleaksUnavailable(SecurityError):
    pass


def find_gitleaks(configured: str | None = None) -> Path | None:
    candidates = [configured, os.environ.get(GITLEAKS_ENV), shutil.which("gitleaks")]
    for c in candidates:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return Path(c)
    return None


class Gitleaks:
    def __init__(self, executable: Path, timeout: int = 900) -> None:
        self.exe = Path(executable)
        self.timeout = timeout

    @classmethod
    def require(cls, configured: str | None, timeout: int = 900) -> "Gitleaks":
        exe = find_gitleaks(configured)
        if exe is None:
            raise GitleaksUnavailable(
                "gitleaks is required (scanner.engine=gitleaks) but was not found. Install gitleaks, "
                f"set scanner.gitleaks_path or ${GITLEAKS_ENV}, or explicitly set scanner.engine=builtin."
            )
        return cls(exe, timeout)

    def version(self) -> str:
        proc = run_command([str(self.exe), "version"], timeout=30)
        return proc.stdout.decode().strip()

    def _run(self, args: list[str], cwd: Path | None = None) -> list[dict[str, Any]]:
        tmp = secure_mkdtemp("ai-safe-gl-")
        try:
            cfg = tmp / "gitleaks.toml"
            cfg.write_text(_CONFIG_TOML)
            ignore_dir = tmp / "ignore"
            ignore_dir.mkdir(mode=0o700)
            report = tmp / "report.json"
            cmd = [
                str(self.exe), *args,
                "--no-banner",
                "--report-format", "json",
                "--report-path", str(report),
                "--exit-code", "0",
                "--log-level", "error",
                "--config", str(cfg),
                "--gitleaks-ignore-path", str(ignore_dir),
                "--ignore-gitleaks-allow",
            ]
            env = safe_env({"GITLEAKS_CONFIG": str(cfg)})
            proc = run_command(cmd, cwd=cwd, env=env, check=False, timeout=self.timeout)
            if proc.returncode != 0:
                raise CommandError(f"gitleaks failed with exit code {proc.returncode}")
            if not report.exists():
                raise CommandError("gitleaks did not produce a report")
            data = json.loads(report.read_text(encoding="utf-8") or "[]")
            if not isinstance(data, list):
                raise CommandError("unexpected gitleaks report format")
            return data
        finally:
            secure_remove_tree(tmp, shred=True)

    def scan_dir(self, path: Path) -> list[dict[str, Any]]:
        path = Path(path).resolve()
        results = self._run(["dir", str(path)], cwd=path)
        return [_normalise(r, path) for r in results]

    def scan_git(self, repo: Path, log_opts: str = "--all") -> list[dict[str, Any]]:
        repo = Path(repo).resolve()
        args = ["git", str(repo)]
        if log_opts:
            args.append(f"--log-opts={log_opts}")
        return [_normalise(r, repo) for r in self._run(args, cwd=repo)]

    def scan_staged(self, repo: Path) -> list[dict[str, Any]]:
        repo = Path(repo).resolve()
        return [_normalise(r, repo) for r in self._run(["git", str(repo), "--staged"], cwd=repo)]

    def scan_unstaged(self, repo: Path) -> list[dict[str, Any]]:
        repo = Path(repo).resolve()
        return [_normalise(r, repo) for r in self._run(["git", str(repo), "--pre-commit"], cwd=repo)]


def _normalise(r: dict[str, Any], root: Path) -> dict[str, Any]:
    f = str(r.get("File", ""))
    if os.path.isabs(f):
        try:
            f = os.path.relpath(f, root)
        except ValueError:
            pass
    f = f.replace(os.sep, "/")
    if f.startswith("./"):
        f = f[2:]
    r = dict(r)
    r["File"] = f
    return r


def load_report(path: Path) -> list[dict[str, Any]]:
    """Load an existing Gitleaks JSON report (``--report-format json``)."""
    data = json.loads(Path(path).read_text(encoding="utf-8") or "[]")
    if not isinstance(data, list):
        raise ValueError("not a gitleaks JSON report (expected a list)")
    for item in data:
        if not isinstance(item, dict) or "RuleID" not in item or "File" not in item:
            raise ValueError("not a gitleaks JSON report (missing RuleID/File)")
    return data
