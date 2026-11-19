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

## What integrate guarantees
- Re-runs the full review and aborts on any blocking issue.
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
- Exit 3: path validation failure, original changed during integration, or agent environment detected.
