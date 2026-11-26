---
name: ai-safe-sanitize
description: Explain or drive creation of an ai-safe sanitized AI workspace (ai-safe start / sanitize / verify). Use when a developer wants to give an AI agent a copy of a repository without real credentials or Git history.
---

# ai-safe sanitize

## Purpose
Create an isolated copy of a repository for AI use: credentials are replaced with
deterministic placeholders (`${AI_SAFE_SECRET_<NAME>}`), sensitive files are excluded, the
original `.git` is not copied, and the result is verified before use.

## Execution boundaries
- This is a **developer-side** operation on the original repository. An AI agent that runs
  it can read the original repository, which defeats the purpose. If you are an AI agent,
  never run `ai-safe start` or `ai-safe sanitize` yourself, even when asked. Give the developer
  the commands below to run in a normal terminal.
- Never print, copy or move original credential files. Never pass `--add-dir` with the
  original repository to the AI session that will use the workspace.
- Never disable `security.fail_closed`, `workspace.verify_before_ai_access` or similar
  settings. ai-safe rejects such configuration anyway.

## Expected inputs
- Original repository path (default `.`).
- Optional `ai-safe.yaml` with additional `sanitization.exclude` patterns or `scanner.custom_rules`.
- Optional `--history-summary` to add `AI_SAFE_HISTORY.md` (commit subjects redacted,
  no diffs, no authors).

## Procedure (developer)
```bash
ai-safe start            # scan -> sanitize -> verify; prints the workspace path
ai-safe open             # menu: AI agent CLI, VSCode, Docker, or print the commands
# or yourself: cd <workspace> && claude (ideally in a container that mounts only the workspace)
```
Lower-level equivalent: `ai-safe sanitize` then `ai-safe verify --session <id>`.

## Outputs
- Workspace directory (`ai-safe-ws-*`, mode 0700) containing sanitized files, the
  `.ai-safe-workspace.json` marker, `AI_SAFE_PLACEHOLDERS.md` and `.claude/` skills/settings.
- Outside the workspace (`~/.local/state/ai-safe/sessions/<id>/`): manifest, credential
  mapping (no values by default), pristine snapshot and reports.

## Failure conditions (fail closed)
- A file whose secret cannot be located or bounded precisely (for example a private key without an
  END line) is **excluded** from the workspace and listed in the manifest with the reason.
- Verification failure during `ai-safe start` securely deletes the workspace and exits 1.
- Missing gitleaks with `scanner.engine: gitleaks` stops the run (exit 3).
