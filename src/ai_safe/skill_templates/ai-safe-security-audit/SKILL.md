---
name: ai-safe-security-audit
description: Audit the security posture of an ai-safe workspace or an ai-safe setup - isolation, leftover secrets, Git metadata, symlinks, credential handling in code - and produce a findings report without exposing secrets. Use when asked for a security check or audit in an ai-safe context.
---

# ai-safe security audit

## Purpose
Produce an evidence-based security report for an ai-safe workspace. The report must contain no
secret values and no claims that are not backed by command output.

## Execution boundaries
- Stay inside the workspace (the directory containing `.ai-safe-workspace.json`).
- Read-only: do not modify files during the audit and do not execute project scripts, tests,
  hooks or installers.
- Do not attempt to prove isolation by trying to escape it. Reading outside the workspace is
  forbidden even "to test" it.
- Never print secret values. Refer to findings by file, line, rule and category.

## Expected inputs
- An ai-safe workspace (current directory), optionally a session id.

## Procedure
1. **Marker**: confirm `.ai-safe-workspace.json` exists and is a regular file.
2. **Workspace verification**: `ai-safe verify` (record PASSED or FAILED and every ERROR or CRITICAL issue).
3. **Change review**: `ai-safe review` (hardcoded credentials, placeholder misuse,
   sensitive files, conflicts).
4. **Code review for credential handling** (read the source files in the workspace):
   - credentials read from environment variables or a secret manager, never literals
   - no logging of request headers, tokens, passwords or full config objects
   - no credentials in URLs, query strings, error messages or exceptions
   - TLS verification not disabled, and no `shell=True`/`eval` on untrusted input
5. **Isolation notes**: state that skills and `.claude/settings.json` are guidance only, and
   recommend running the agent as a separate OS user or in a container that mounts only the
   workspace.
6. **Report** using the template below.

## Outputs
A plain-text report in this format (no secret values):
```
ai-safe security audit
Workspace marker: present | missing
ai-safe verify: PASSED | FAILED  (n critical, n errors, n warnings)
ai-safe review: PASSED | FAILED  (n blocking)
Findings:
  [SEVERITY] file:line - rule/category - description - recommended fix
Placeholder requirements:
  NAME - where - how it is supplied
Limitations:
  Pattern-based detection cannot find every secret. This audit did not test OS isolation.
```

## Failure conditions
- Marker missing, `.git` present, private key present, or any CRITICAL issue: report
  **FAIL**, stop further work, and tell the developer to recreate the workspace with `ai-safe start`.
