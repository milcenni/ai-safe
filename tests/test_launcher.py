import subprocess

import pytest
from typer.testing import CliRunner

from ai_safe import launcher
from ai_safe.cli import app
from conftest import builtin_config, prepare, write


def _project(make_repo, fake, *, allow_launch: bool, docker_image: str | None = None):
    key = fake.openai()
    repo = make_repo({
        ".gitignore": ".env\n",
        "app/settings.py": f'API_KEY = "{key}"\n',
        "README.md": "# demo\n",
    })
    yaml = "scanner:\n  engine: builtin\nsecurity:\n"
    yaml += f"  allow_ai_launch: {'true' if allow_launch else 'false'}\n"
    if docker_image:
        yaml += f"  docker_image: {docker_image}\n"
    write(repo, {"ai-safe.yaml": yaml})
    cfg = builtin_config(security__allow_ai_launch=allow_launch, security__docker_image=docker_image)
    p = prepare(repo, cfg)
    assert p.verification.passed
    return p


@pytest.fixture
def project(make_repo, fake):
    return _project(make_repo, fake, allow_launch=False)


@pytest.fixture
def project_allow_launch(make_repo, fake):
    return _project(make_repo, fake, allow_launch=True)


@pytest.fixture
def project_docker(make_repo, fake):
    return _project(make_repo, fake, allow_launch=True, docker_image="example/claude-code:1")


class Recorder:
    def __init__(self, rc: int = 0):
        self.calls = []
        self.rc = rc

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, self.rc)


def _forbid(*a, **kw):
    raise AssertionError("subprocess.run must not be called")


def _open(p, monkeypatch, input=None):
    monkeypatch.chdir(p.repo)
    return CliRunner().invoke(app, ["open", "-s", p.session.id], input=input)


def test_open_refuses_inside_agent(project, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    r = _open(project, monkeypatch)
    assert r.exit_code == 3, r.output
    assert "developer" in r.output


def test_open_prints_only_when_launch_disallowed(project, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project, monkeypatch)
    assert r.exit_code == 0, r.output
    assert "code -n" in r.output
    assert "allow_ai_launch: true" in r.output
    assert str(project.ws) in r.output


def test_open_non_tty_prints_and_exits_2(project_allow_launch, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher, "is_interactive", lambda: False)
    r = _open(project_allow_launch, monkeypatch)
    assert r.exit_code == 2, r.output
    assert "code -n" in r.output


def test_open_vscode_choice_runs_code(project_allow_launch, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(launcher.subprocess, "run", rec)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="2\n")
    assert r.exit_code == 0, r.output
    assert [c[0] for c in rec.calls] == [["code", "-n", str(project_allow_launch.ws)]]
    assert "shell" not in rec.calls[0][1]


def test_open_agent_env_is_allowlisted(project_allow_launch, monkeypatch):
    monkeypatch.setenv("SOME_TOKEN", "x")
    rec = Recorder()
    monkeypatch.setattr(launcher.subprocess, "run", rec)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="1\n")
    assert r.exit_code == 0, r.output
    (argv, kw), = rec.calls
    assert argv == ["claude"]
    assert kw["env"]["AI_SAFE_AGENT"] == "1"
    assert "SOME_TOKEN" not in kw["env"]
    assert kw["cwd"] == project_allow_launch.ws


def test_open_agent_missing_executable_prints_example(project_allow_launch, monkeypatch):
    def missing(*a, **kw):
        raise FileNotFoundError("claude")

    monkeypatch.setattr(launcher.subprocess, "run", missing)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="1\n")
    assert r.exit_code == 3, r.output
    assert f"cd {project_allow_launch.ws} && claude" in r.output


def test_open_docker_without_image_prints_example(project_allow_launch, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="3\n")
    assert "<image-with-claude-code>" in r.output
    assert "set security.docker_image" in r.output


def test_open_docker_failure_prints_example(project_docker, monkeypatch, fake):
    secret = fake.openai()
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    rec = Recorder(rc=125)
    monkeypatch.setattr(launcher.subprocess, "run", rec)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_docker, monkeypatch, input="3\n")
    ws = project_docker.ws
    (argv, kw), = rec.calls
    assert argv == ["docker", "run", "--rm", "-it", "-v", f"{ws}:/workspace", "-w", "/workspace",
                    "-e", "AI_SAFE_AGENT=1", "-e", "ANTHROPIC_API_KEY", "example/claude-code:1", "claude"]
    assert secret not in " ".join(argv)
    assert secret not in r.output
    assert "<image-with-claude-code>" in r.output
    assert "set security.docker_image" in r.output


def test_open_docker_without_docker_binary_not_run(project_docker, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: None)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_docker, monkeypatch, input="3\n")
    assert "<image-with-claude-code>" in r.output


def test_open_print_choice_prints_all(project_allow_launch, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="4\n")
    assert r.exit_code == 0, r.output
    ws = project_allow_launch.ws
    assert f"cd {ws} && claude" in r.output and f"code -n {ws}" in r.output
    assert "<image-with-claude-code>" in r.output


def test_open_refuses_unverified_session(project, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    project.session.verified_tree_hash = None
    project.session.save()
    r = _open(project, monkeypatch)
    assert r.exit_code == 1, r.output


def test_open_refuses_missing_workspace(project, monkeypatch):
    import shutil

    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    shutil.rmtree(project.ws)
    r = _open(project, monkeypatch)
    assert r.exit_code == 1, r.output


def test_launch_options_keys(project_allow_launch):
    opts = launcher.launch_options(project_allow_launch.ws, project_allow_launch.cfg)
    assert [o.key for o in opts] == ["agent", "vscode", "docker", "print"]
    assert opts[3].argv is None


def test_open_invalid_choice_launches_nothing(project_allow_launch, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", _forbid)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="9\n")
    assert r.exit_code == 2, r.output


GUI_VARS = {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/1_interop", "WSLENV": "X/p"}


def test_open_vscode_env_keeps_display_and_wsl_vars(project_allow_launch, monkeypatch):
    for k, v in GUI_VARS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SOME_TOKEN", "x")
    rec = Recorder()
    monkeypatch.setattr(launcher.subprocess, "run", rec)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="2\n")
    assert r.exit_code == 0, r.output
    (argv, kw), = rec.calls
    assert argv[0] == "code"
    for k, v in GUI_VARS.items():
        assert kw["env"][k] == v
    assert kw["env"]["AI_SAFE_AGENT"] == "1" and "SOME_TOKEN" not in kw["env"]


def test_open_agent_env_has_no_display_or_wsl_vars(project_allow_launch, monkeypatch):
    for k, v in GUI_VARS.items():
        monkeypatch.setenv(k, v)
    rec = Recorder()
    monkeypatch.setattr(launcher.subprocess, "run", rec)
    monkeypatch.setattr(launcher, "is_interactive", lambda: True)
    r = _open(project_allow_launch, monkeypatch, input="1\n")
    assert r.exit_code == 0, r.output
    (argv, kw), = rec.calls
    assert argv == ["claude"]
    assert not set(GUI_VARS) & set(kw["env"])
