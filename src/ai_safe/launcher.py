"""Launch options for `ai-safe open` (developer-only, never automatic).

Every launch is an argv list run without a shell. Environment variable values
never appear in argv or output: Docker gets ``-e NAME`` and reads the value
itself.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ai_safe.config import AISafeConfig

IMAGE_PLACEHOLDER = "<image-with-claude-code>"


@dataclass
class LaunchOption:
    key: str
    label: str
    argv: list[str] | None
    example: str


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def launch_env(cfg: AISafeConfig) -> dict[str, str]:
    """Only allowlisted variables from the current environment, plus AI_SAFE_AGENT=1."""
    allowed = set(cfg.security.launch_env_allowlist)
    env = {k: v for k, v in os.environ.items() if k in allowed}
    env["AI_SAFE_AGENT"] = "1"
    return env


# VSCode (an Electron GUI) cannot start on Linux/WSL without its display/session variables.
# They locate the display and session bus; they are not credentials. Agent and Docker never get them.
VSCODE_ENV_VARS = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
                   "WSL_DISTRO_NAME", "WSL_INTEROP", "WSLENV")


def option_env(opt: LaunchOption, cfg: AISafeConfig) -> dict[str, str]:
    """The environment for ``opt``: :func:`launch_env`, plus ``VSCODE_ENV_VARS`` (when set) for vscode only."""
    env = launch_env(cfg)
    if opt.key == "vscode":
        env.update({k: os.environ[k] for k in VSCODE_ENV_VARS if k in os.environ})
    return env


def _join(argv: list[str]) -> str:
    return " ".join(a if a == IMAGE_PLACEHOLDER else shlex.quote(a) for a in argv)


def _docker_argv(ws: Path, cfg: AISafeConfig, image: str) -> list[str]:
    env_names = [n for n in cfg.security.launch_env_allowlist if n.startswith("ANTHROPIC_") and os.environ.get(n)]
    argv = ["docker", "run", "--rm", "-it", "-v", f"{ws}:/workspace", "-w", "/workspace", "-e", "AI_SAFE_AGENT=1"]
    for name in env_names:
        argv += ["-e", name]  # name only: docker reads the value from its own environment
    return argv + [image, "claude"]


def launch_options(ws: Path, cfg: AISafeConfig) -> list[LaunchOption]:
    sec = cfg.security
    agent = LaunchOption("agent", "AI agent CLI (" + _join(sec.launch_command) + ")", list(sec.launch_command),
                         f"cd {shlex.quote(str(ws))} && {_join(sec.launch_command)}")
    vscode_argv = ["code", "-n", str(ws)]
    vscode = LaunchOption("vscode", "VSCode (new window)", vscode_argv, _join(vscode_argv))
    docker_argv = None
    if sec.docker_image and shutil.which("docker"):
        docker_argv = _docker_argv(ws, cfg, sec.docker_image)
    docker = LaunchOption("docker", "Docker container (mounts only the workspace)", docker_argv,
                          _join(_docker_argv(ws, cfg, IMAGE_PLACEHOLDER)))
    examples = "\n".join(o.example for o in (agent, vscode, docker))
    return [agent, vscode, docker, LaunchOption("print", "Print the commands only", None, examples)]


def run_option(opt: LaunchOption, ws: Path, env: dict[str, str]) -> int:
    """Run the option's argv (no shell) in the workspace. 127 if the executable is missing."""
    if opt.argv is None:
        raise ValueError(f"launch option {opt.key} has no command")
    try:
        return subprocess.run(opt.argv, cwd=ws, env=env, check=False).returncode
    except FileNotFoundError:
        return 127
