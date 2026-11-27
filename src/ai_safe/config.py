"""Configuration loading and validation (``ai-safe.yaml``).

All configuration is validated before any command runs. Settings that would
weaken a mandatory control (e.g. ``auto_push: true``) are rejected rather than
silently ignored.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ai_safe.models import Category

CONFIG_FILENAME = "ai-safe.yaml"

# Paths that are never copied into the AI workspace, regardless of config.
MANDATORY_EXCLUDES: tuple[str, ...] = (
    ".git/",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "*.ppk",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".ssh/",
    ".gnupg/",
    ".aws/",
    ".azure/",
    ".kube/",
    ".docker/",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
    "credentials.json",
    "*.tfstate",
    "*.tfstate.backup",
    "*.tfvars",
    # Claude Code project settings can contain tokens and hooks; ai-safe
    # generates its own .claude/ inside the workspace instead.
    ".claude/",
    # local ai-safe installation (install.sh --local)
    ".ai-safe/",
    # ai-safe's own per-project data under .claude/
    ".claude/ai-safe/",
)

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "credentials.json",
    "secrets/",
    ".ssh/",
    "service-account*.json",
    "*.secret",
    "*.secrets",
    "secrets.*",
    "kubeconfig",
    ".terraform/",
)

DEFAULT_BINARY_ALLOW: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class CustomRule(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    description: str = ""
    regex: str
    category: Category = Category.GENERIC_SECRET
    secret_group: int | str = "secret"

    @model_validator(mode="after")
    def _check_regex(self) -> "CustomRule":
        try:
            compiled = re.compile(self.regex)
        except re.error as exc:
            raise ValueError(f"custom rule {self.id!r}: invalid regex: {exc}") from None
        if isinstance(self.secret_group, str):
            if self.secret_group not in compiled.groupindex:
                if compiled.groups == 0:
                    self.__dict__["secret_group"] = 0
                else:
                    raise ValueError(
                        f"custom rule {self.id!r}: regex has no group named {self.secret_group!r}"
                    )
        elif self.secret_group > compiled.groups:
            raise ValueError(f"custom rule {self.id!r}: secret_group out of range")
        return self


class ScannerConfig(_Strict):
    engine: Literal["gitleaks", "builtin"] = "gitleaks"
    gitleaks_path: str | None = None
    builtin_rules: bool = True
    scan_git_history: bool = True
    history_log_opts: str = "--all"
    scan_untracked: bool = True
    scan_ignored: bool = True
    scan_staged: bool = True
    scan_unstaged: bool = True
    scan_commit_messages: bool = True
    max_file_size_kb: int = Field(default=2048, ge=1, le=1024 * 1024)
    ignored_skip_dirs: list[str] = Field(
        default_factory=lambda: ["node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".ai-safe"]
    )
    timeout_seconds: int = Field(default=900, ge=10)
    custom_rules: list[CustomRule] = Field(default_factory=list)

    @field_validator("history_log_opts")
    @classmethod
    def _log_opts(cls, v: str) -> str:
        # Allowlist: git accepts abbreviated long options (e.g. --outp=...),
        # so blocklisting dangerous options is not enough.
        allowed = re.compile(
            r"--(?:all|branches|tags|remotes|first-parent|no-merges|full-history|reflog)"
            r"|--(?:branches|tags|remotes|glob|since|until|after|before|max-count|skip)=[A-Za-z0-9_./*:@^~-]+"
            r"|[A-Za-z0-9_./^~@][A-Za-z0-9_./^~@:-]*"  # revisions / ranges (no leading dash)
        )
        for tok in v.split():
            if not allowed.fullmatch(tok):
                raise ValueError(f"history_log_opts: unsupported option {tok!r}")
        return v


class PlaceholderConfig(_Strict):
    enabled: bool = True
    deterministic: bool = True


class SanitizationConfig(_Strict):
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    include_ignored_files: bool = False
    allowed_binary_extensions: list[str] = Field(default_factory=lambda: list(DEFAULT_BINARY_ALLOW))
    preserve_permissions: bool = True
    history_summary: bool = False
    history_summary_max_commits: int = Field(default=200, ge=1, le=100000)
    placeholders: PlaceholderConfig = Field(default_factory=PlaceholderConfig)
    # Email addresses (internal staff, customers) are personal data: replaced by default.
    sanitize_emails: bool = True

    @field_validator("exclude")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        for p in v:
            if not p or p.strip() != p or "\x00" in p:
                raise ValueError(f"invalid exclude pattern: {p!r}")
        return v

    @field_validator("allowed_binary_extensions")
    @classmethod
    def _exts(cls, v: list[str]) -> list[str]:
        out = []
        for e in v:
            e = e.lower()
            if not e.startswith("."):
                e = "." + e
            out.append(e)
        return out

    def all_excludes(self) -> list[str]:
        seen: dict[str, None] = {}
        for p in (*MANDATORY_EXCLUDES, *self.exclude):
            seen[p] = None
        return list(seen)


class WorkspaceConfig(_Strict):
    isolated: bool = True
    include_git_history: bool = False
    verify_before_ai_access: bool = True
    base_dir: str | None = None
    state_dir: str | None = None
    generate_claude_settings: bool = True
    install_skills: bool = True

    @field_validator("isolated", "verify_before_ai_access")
    @classmethod
    def _must_be_true(cls, v: bool, info) -> bool:
        if not v:
            raise ValueError(f"workspace.{info.field_name}=false is not supported (fail-closed design)")
        return v

    @field_validator("include_git_history")
    @classmethod
    def _no_history(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "workspace.include_git_history=true is not supported: original Git history is never "
                "exposed to AI. Use sanitization.history_summary for a redacted summary."
            )
        return v


class IntegrationConfig(_Strict):
    require_approval: bool = True
    auto_commit: bool = False
    auto_push: bool = False
    allow_deletions: bool = True
    run_final_scan: bool = True

    @field_validator("require_approval", "run_final_scan")
    @classmethod
    def _must_be_true(cls, v: bool, info) -> bool:
        if not v:
            raise ValueError(f"integration.{info.field_name}=false is not supported")
        return v

    @field_validator("auto_commit", "auto_push")
    @classmethod
    def _must_be_false(cls, v: bool, info) -> bool:
        if v:
            raise ValueError(f"integration.{info.field_name}=true is not supported: ai-safe never commits or pushes")
        return v


class SecurityConfig(_Strict):
    fail_closed: bool = True
    redact_logs: bool = True
    reject_symlinks: bool = True
    store_secret_values: bool = False
    encrypt_mapping: bool = True
    allow_ai_launch: bool = False
    launch_command: list[str] = Field(default_factory=lambda: ["claude"])
    docker_image: str | None = None
    launch_env_allowlist: list[str] = Field(
        default_factory=lambda: [
            "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "TZ",
            "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME",
        ]
    )

    @field_validator("fail_closed", "redact_logs")
    @classmethod
    def _must_be_true(cls, v: bool, info) -> bool:
        if not v:
            raise ValueError(f"security.{info.field_name}=false is not supported")
        return v

    @field_validator("docker_image")
    @classmethod
    def _docker_image(cls, v: str | None) -> str | None:
        # Allowlist: the value ends up on a docker command line, so it must not
        # start with "-" (option injection) or contain whitespace/shell metacharacters.
        if v is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", v):
            raise ValueError("invalid image reference (allowed: [A-Za-z0-9][A-Za-z0-9._/:@-]{0,254})")
        return v

    @model_validator(mode="after")
    def _mapping(self) -> "SecurityConfig":
        if self.store_secret_values and not self.encrypt_mapping:
            raise ValueError("security.store_secret_values requires security.encrypt_mapping=true")
        if not self.launch_command:
            raise ValueError("security.launch_command must not be empty")
        return self


class AISafeConfig(_Strict):
    version: Literal[1] = 1
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    sanitization: SanitizationConfig = Field(default_factory=SanitizationConfig)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    integration: IntegrationConfig = Field(default_factory=IntegrationConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @model_validator(mode="after")
    def _ignored_files_scanned(self) -> "AISafeConfig":
        if self.sanitization.include_ignored_files and not self.scanner.scan_ignored:
            raise ValueError(
                "sanitization.include_ignored_files=true requires scanner.scan_ignored=true "
                "(ignored files would be copied unscanned)"
            )
        return self


class ConfigError(Exception):
    pass


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        lines.append(f"  - {loc or '<root>'}: {err['msg']}")
    return "invalid configuration:\n" + "\n".join(lines)


def parse_config(data: object) -> AISafeConfig:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError("invalid configuration: top level must be a mapping")
    try:
        return AISafeConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from None


def load_config(path: Path | None = None, repo: Path | None = None) -> AISafeConfig:
    """Load and validate configuration.

    Resolution: explicit ``path`` > ``<repo>/ai-safe.yaml`` > built-in defaults.
    """
    if path is None and repo is not None:
        candidate = Path(repo) / CONFIG_FILENAME
        if candidate.is_file():
            path = candidate
    if path is None:
        return AISafeConfig()
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    if path.is_symlink():
        raise ConfigError("configuration file must not be a symlink")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path.name}: {exc.__class__.__name__}") from None
    return parse_config(data)


DEFAULT_CONFIG_YAML = """\
# ai-safe configuration. Validated before every command.
version: 1

scanner:
  engine: gitleaks          # gitleaks | builtin  (builtin rules always run in addition)
  # gitleaks_path: /usr/local/bin/gitleaks
  scan_git_history: true
  history_log_opts: "--all" # all reachable branches and tags
  scan_untracked: true
  # false = files ignored by .gitignore are NOT scanned (then include_ignored_files must stay false)
  scan_ignored: true
  scan_staged: true
  scan_unstaged: true
  scan_commit_messages: true
  max_file_size_kb: 2048
  custom_rules: []
  # custom_rules:
  #   - id: internal-service-token
  #     description: Internal service token
  #     regex: "isvc_(?P<secret>[A-Za-z0-9]{32})"
  #     category: ACCESS_TOKEN

sanitization:
  exclude:
    - .env
    - .env.*
    - "*.pem"
    - "*.key"
    - credentials.json
    - secrets/
    - .ssh/
  include_ignored_files: false
  history_summary: false
  sanitize_emails: true      # false = email addresses are not detected or replaced
  placeholders:
    enabled: true
    deterministic: true

workspace:
  isolated: true
  include_git_history: false
  verify_before_ai_access: true
  # base_dir: /path/outside/the/repo   # default: system temp dir
  # state_dir: ~/.local/state/ai-safe

integration:
  require_approval: true
  auto_commit: false
  auto_push: false
  allow_deletions: true

security:
  fail_closed: true
  redact_logs: true
  reject_symlinks: true
  store_secret_values: false   # true = keep an encrypted copy of original values (needs passphrase)
  encrypt_mapping: true
  allow_ai_launch: false
  launch_command: ["claude"]
  # docker_image: ghcr.io/you/claude-code:tag
"""
