---
name: ai-safe-review
description: Review AI-generated changes in an ai-safe workspace for hardcoded credentials, placeholder misuse, sensitive file changes, symlinks and integration conflicts. Use after finishing an implementation task in an ai-safe workspace, before handing work back to the developer.
---

# ai-safe review

## Purpose
Compare the workspace with its pristine snapshot (stored outside the workspace) and report
anything that must not reach the original repository.

## Execution boundaries
- Run `ai-safe review` from inside the workspace. It reads files only and never executes
  scripts, tests, hooks or build steps from the workspace.
- Do not edit `.ai-safe-workspace.json` or the security tool configuration to make the review
  pass.
- Fix issues by changing the code in the workspace, never by weakening checks.

## Expected inputs
- Current directory inside an ai-safe workspace (or `--session <id>`).

## Procedure
1. `ai-safe review`
2. For each issue:
   - `hardcoded-credential` / `gitleaks` / `known-secret`: remove the literal and read it from
     an environment variable instead.
   - `placeholder-in-new-code`: do not copy `${AI_SAFE_SECRET_...}` into new lines. Use an
     environment lookup and report a placeholder requirement.
   - `placeholder-replaced` / `unknown-placeholder`: restore the original placeholder line or
     replace it with an environment lookup. Never invent placeholder names.
   - `sensitive-file` / `security-config`: revert the change (for example delete the `.env` you created).
   - `symlink`, `unexpected-binary`, `unsafe-path`: remove the offending file.
   - `conflict`: explain it to the developer. They will apply that hunk manually.
   - `sensitive-config` (warning): mention it explicitly in your hand-off summary.
3. Re-run `ai-safe review` until it passes, then run `ai-safe verify`.
4. Hand off with: summary of changes, warnings, placeholder requirements, and the
   instruction that the **developer** runs `ai-safe integrate`.

## Outputs
- Terminal report and `reports/review.json` in the session state directory.
- Exit code `0` = no blocking issues, `1` = blocking issues, `3` = operational error.

## Failure conditions
- "session snapshot missing" / "workspace marker is invalid or tampered": stop and tell the
  developer. The workspace can no longer be trusted. Recreate it with `ai-safe start`.
