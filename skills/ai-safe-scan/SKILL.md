---
name: ai-safe-scan
description: Run and interpret an ai-safe secret scan (working tree, staged and unstaged changes, ignored files, full Git history) without ever displaying secret values. Use when the user asks to scan a repository or workspace for credentials.
---

# ai-safe scan

## Purpose
Discover credentials in a project and summarise them by location and category. The
output contains rule ids, files, lines, commits and keyed fingerprints. It never
contains secret values.

## Execution boundaries
- Run only `ai-safe scan` (optionally with `--no-history`, `--report <file>`,
  `--gitleaks-report <file>`, `--config <file>`).
- Do not open the reported files to "look at" the secret. Do not use `grep`, `cat`, `git show`
  or `git log -p` to view values.
- If you are inside an ai-safe workspace, scan only the workspace (`ai-safe scan .`).
  Never scan paths outside it.
- If you are an AI agent and the target is the developer's original repository, do not run
  the scan yourself, even when asked: you would already have access to that repository. Give
  the developer the command to run in a normal terminal instead.
- Scanning is read-only: it never modifies files, the index or Git history.

## Expected inputs
- A directory (default `.`): a Git repository or a plain directory.
- Optional `ai-safe.yaml` (validated before running).
- `gitleaks` on PATH, unless `scanner.engine: builtin` is configured.

## Procedure
1. `ai-safe scan --report scan-report.json` (when the developer scans an original repository,
   the report path must be outside any AI workspace).
2. Summarise: totals by category (API_KEY, ACCESS_TOKEN, PASSWORD, DATABASE_CREDENTIAL,
   PRIVATE_KEY, SSH_KEY, CLOUD_CREDENTIAL, JWT_SECRET, GENERIC_SECRET) and by location
   (tracked, untracked, ignored, staged, unstaged, history).
3. If any finding has location `history`, state clearly that the credential has been
   exposed and **must be rotated**. Sanitization does not undo prior exposure, and ai-safe
   never rewrites history.

## Outputs
- Rich table in the terminal and an optional JSON report (no secret values).
- Exit code `0` = nothing detected, `1` = findings, `2` = configuration error, `3` = operational error.

## Failure conditions
- Exit code 2: fix `ai-safe.yaml` (the error lists the offending key).
- Exit code 3 with "gitleaks is required": install gitleaks or set `scanner.engine: builtin`
  deliberately. Do not work around the check.
- Pattern matching cannot prove absence. A clean scan does not guarantee that there are no secrets.
