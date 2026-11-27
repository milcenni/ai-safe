---
name: ai-safe-integrate
description: Guide a developer through integrating reviewed AI changes from an ai-safe workspace into the original repository. Use when work in an ai-safe workspace is finished and the user asks how to bring the changes back.
---

# ai-safe integrate

## Purpose
Apply reviewed AI changes to the original repository with a patch-based, fail-closed
process that preserves the original credentials and never commits or pushes.

## Execution boundaries
- **An AI agent must not run `ai-safe integrate`.** The command refuses to run when it detects
  an AI agent environment (for example `CLAUDECODE`) or when run from inside the workspace,
  because integration requires the developer's explicit, informed approval.
- Your role is to prepare: make sure `ai-safe review` passes, then give the developer the
  exact command and a summary of what will change.
- When only some of your changes are ready, you may **suggest** `ai-safe integrate --only <path>`
  (repeatable) or `ai-safe integrate --select` to the developer, with the paths and why. Never run
  either yourself. Mention any file the selected ones depend on that you added (ai-safe also warns).
- Never suggest bypassing the agent check, editing the snapshot, or restoring credentials
  into AI-written lines.

## Expected inputs
- A session whose `ai-safe review` passes.
- Developer at a normal terminal in the original repository (or with `--session <id>`).

## Procedure (developer)
```bash
ai-safe review                 # optional; integrate re-runs it anyway
ai-safe integrate --dry-run    # builds and records the redacted patch only
ai-safe integrate              # shows the patch, asks you to type 'apply'
git diff                       # inspect; run tests; commit yourself
```
Use `--exclude <path>` to leave specific files out.

Integrate only some files; the rest stay in the workspace:
```bash
ai-safe integrate --only src/a.php --only src/lib/      # file or directory prefix (repeatable)
ai-safe integrate --only 'app/Controllers/*.php'        # glob against the repo-relative path
ai-safe integrate --select                              # pick rows: 1,3-5 / all / none
```
`--only` and `--select` cannot be combined; `--exclude` wins over `--only`. A pattern that
matches no changed file is an error. Files integrated this way are not offered again; resync
runs without `--discard` once everything is integrated.

## What integrate guarantees
- Re-runs the full review on every change and aborts on any blocking issue. With `--only` or
  `--select`, errors in files that are not selected are reported but do not block (those
  files are not written); changes to ai-safe itself or an original credential value in AI
  output block whatever is selected. A rename is integrated as a pair.
- Validates every path: no traversal, no symlinked components, no `.git`, no excluded or
  sensitive files, no overwriting files that were never shared with the AI.
- Aborts if an original file changed since the workspace was created.
- Never writes placeholders into the original. Hunks that would require restoring a real
  credential into an AI-written line are rejected as conflicts.
- Runs a final Gitleaks and builtin scan on the resulting content and aborts on any new credential.
- Writes atomically, keeps original file modes, writes a redacted patch record to the
  session state directory, and never commits or pushes.

## Outputs
- Changed files in the original working tree (uncommitted).
- `patches/<timestamp>.patch` (credential lines masked) and `reports/integration.json`.

## Failure conditions
- Exit 1: review/final scan failed or approval not given. Nothing was written.
- Exit 2: an `--only` pattern matched no changed file, `--only` with `--select`, or
  `--select` without an interactive terminal.
- Exit 3: path validation failure, original changed during integration, or agent environment detected.
