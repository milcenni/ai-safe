# AGENTS.md: instructions for AI coding agents

This repository is **ai-safe**, a CLI that keeps real credentials and Git history away from AI coding
agents. Read this file before doing anything in this repository, or before installing ai-safe for a user.

## 1. Credential exposure rule (always applies)

If at any point you notice that a **real credential has entered your context**, you must:

1. **Stop** the current action before your next tool call.
2. **Tell the user** what kind of credential it is (API key, token, password, private key, …) and where
   it came from (file path and line, command output, or pasted text).
3. **Never repeat the value**, not even partially or masked with its first or last characters. Do not use
   it, copy it, store it, log it, or put it into files, commits, PR descriptions, memory or notes.
4. **Recommend rotation.** It was sent to the model provider as part of your context, and that cannot be
   undone. Suggest keeping it out of the repository (`.gitignore`, a secret manager, or the ai-safe
   workflow).
5. **Ask how to proceed** and wait for an explicit answer before continuing the task.

Examples: an `.env` value printed by `cat`, a token in a settings file you listed, a password in a config
file you opened, a key in command output or a stack trace.

Do not treat obviously synthetic test values, placeholders such as `${AI_SAFE_SECRET_...}`, or
documentation examples as exposures.

> This rule is guidance for you, not a security control. Real protection comes from never letting an
> agent read the credential in the first place. That is what ai-safe is for.

## 2. Installing ai-safe for a user

Follow these steps in order, and ask the user before each decision. Never assume consent.

1. **Ask where to install.**
   - **Global:** for the user's account. Installs `~/.local/share/ai-safe`, `~/.local/bin/ai-safe` and
     skills in `~/.claude/skills/`.
   - **Local:** inside one project. Installs `<project>/.ai-safe/`, skills in `<project>/.claude/skills/`,
     and `<project>/ai-safe.yaml`.

     If they choose local, ask which project directory to use.
2. **Pre-installation: ensure Git repository.** ai-safe works on a Git repository. Check the project
   directory (the one you will protect, or the local install target):

   ```bash
   git rev-parse --git-dir 2>/dev/null || git init
   ```

   Run `git init` only after asking the user. Never create commits for them.
3. **Ask for consent to download.** The installer fetches Python packages from PyPI (typer, rich,
   pydantic, PyYAML, cryptography). It also downloads the official Gitleaks release from GitHub, unless
   Gitleaks 8.19+ is already installed, and verifies its SHA-256 checksum.
4. **Run the installer** from this repository's root. Pass `--yes` only after the user agreed in step 3.

   ```bash
   ./install.sh --global --yes
   ./install.sh --local /path/to/project --yes
   ```

   Useful flags: `--no-gitleaks` (the user declines the Gitleaks download), `--force` (reinstall or
   overwrite the ai-safe skills), `--uninstall --global|--local DIR`.
5. **Ask before setting `scanner.scan_ignored`.** The default (`true`) scans files that `.gitignore`
   ignores. If the user wants `false`, set it in `ai-safe.yaml` only after they say so, and keep
   `sanitization.include_ignored_files: false` (the combination is rejected). Do not open, list or read
   ignored files to help decide. Recommend `.gitignore` entries for `.ai-safe/` and
   `.claude/settings.local*.json` only, and add them after asking.
6. **Verify the install.**

   ```bash
   ai-safe version                          # global (needs ~/.local/bin on PATH)
   /path/to/project/.ai-safe/bin/ai-safe version   # local
   ```

   Expected output: `ai-safe 0.1.0  (gitleaks: 8.x.y)`. If it says `gitleaks: not found`, tell the user
   that ai-safe will refuse to scan until Gitleaks is installed or they deliberately set
   `scanner.engine: builtin`.
7. **Explain the next step and hand over.** The user runs `ai-safe start` and then `ai-safe open`
   themselves, in a normal terminal, inside the repository they want to protect (see §5).

Requirements: Linux or macOS, Python 3.11+ (3.12+ recommended), Git and curl. No sudo is needed and
nothing is installed system-wide.

## 3. Boundaries when working with ai-safe

- **Never run `ai-safe integrate`, `ai-safe cleanup`, `ai-safe resync` or `ai-safe open`.** Integration
  requires the developer's typed approval, and integrate, resync and open refuse to run inside an AI agent
  session. Give the user the command instead.
- **Don't run `ai-safe start`, `sanitize` or `scan` on a user's repository unless they explicitly ask.**
  An agent that runs them in the original repository already has access to that repository, which
  defeats the purpose. The output is redacted, but say this to the user.
- **Never read** `.env*` files, private keys, `~/.local/state/ai-safe/`, or credential stores (`~/.aws`,
  `~/.ssh`, `.npmrc`, `.netrc`, …).
- **Never weaken ai-safe's configuration** (`fail_closed`, `require_approval`, exclusions, …) to make
  something pass.
- **Inside an ai-safe workspace** (a directory with `.ai-safe-workspace.json`), follow
  `.claude/skills/ai-safe/SKILL.md`.

## 4. Developing this repository

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q          # set AI_SAFE_GITLEAKS=/path/to/gitleaks to include gitleaks tests
```

- **Layout:** source in `src/ai_safe/`, tests in `tests/`, skills in `src/ai_safe/skill_templates/`.
  Keep `skills/` an identical copy of the skill templates; a test enforces this.
- **Tests use synthetic credentials only.** Generate random credential-shaped values at runtime (see
  `tests/conftest.py::Fake`). Never commit real credentials, and never write literal credential-shaped
  strings into source, docs or skills; a test scans the skills.
- **Security changes:** fail closed, never put secret values in messages or logs, add a regression test,
  and update `SECURITY.md`.
- **Never** add automatic commit or push behavior. No automatic launch; `ai-safe open` launches only on a
  human's menu choice with `allow_ai_launch: true`.

## 5. Opening a session in the workspace

When the user asks for implementation work in their main project, do not start it there. Tell them to run,
in a normal terminal inside that repository:

```bash
ai-safe start   # scan, sanitize and verify; prints the workspace path
ai-safe open    # menu: AI agent CLI, VSCode, Docker, or print the commands
```

Instead of `ai-safe open` they can start the session themselves: `cd <ws> && claude`, or `code -n <ws>`,
where `<ws>` is the printed workspace path. Inside the workspace you may work freely, within its
`ai-safe` skill.

**Refreshing the workspace.** When the original repository has moved on, the user runs `ai-safe resync`.
It rebuilds the workspace in a staging directory, verifies it there, and only then replaces the workspace
contents in place, so the path stays the same. Ask the user to close the AI session in the workspace
first. Resync refuses while the workspace holds changes that were not integrated: the user either runs
`ai-safe integrate` first, or `ai-safe resync --discard` and types `discard`. Never suggest `--discard`
without saying that it throws the AI's work away.
