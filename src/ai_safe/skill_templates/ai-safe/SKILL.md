---
name: ai-safe
description: Operating rules for working inside an ai-safe sanitized workspace. Use at the start of every task in a directory that contains .ai-safe-workspace.json, and whenever credentials, configuration, environment variables or AI_SAFE_SECRET placeholders are involved.
---

# Working inside an ai-safe workspace

This directory is a **sanitized copy** of a project. Real credentials were replaced with
placeholders such as `${AI_SAFE_SECRET_DB_PASSWORD}`, sensitive files (`.env`, keys,
credential stores) were removed, and the original Git history is not present.

> This skill is guidance, not a security boundary. Isolation is enforced by the operating
> system, sandbox or container that runs you. Never try to test or bypass it.

## Expected inputs
- A task from the developer.
- The current directory: an ai-safe workspace containing `.ai-safe-workspace.json`,
  `AI_SAFE_PLACEHOLDERS.md` and (optionally) `AI_SAFE_HISTORY.md`.

## Outputs
- Code changes inside the workspace only.
- A hand-off summary that includes changed files, any placeholder requirements (section 4),
  and the results of `ai-safe verify` and `ai-safe review`.

## 1. Confirm the workspace first

Before doing anything else:

1. Check that `.ai-safe-workspace.json` exists in the workspace root.
2. If it does not exist, **stop** and tell the user: "This is not an ai-safe workspace.
   Run `ai-safe start` and then `ai-safe open` in your own terminal, in the original
   repository." Do not run either command yourself.
3. Treat the directory containing `.ai-safe-workspace.json` as the only directory you may
   read, search or modify.

## 2. Execution boundaries (always)

- Never request, ask for, guess, brute-force or reconstruct real credentials.
- Never read, list or search parent directories or any path outside this workspace.
  Do not use `..`, absolute paths to other projects, `find /`, `grep -r ~`, or similar.
- Never look for the original repository, its `.git` directory, `~/.local/state/ai-safe`,
  shell history, keychains, cloud CLI config (`~/.aws`, `~/.config/gcloud`, `~/.kube`),
  SSH keys or browser data.
- Never create, read or modify `.env` or `.env.*` files, private keys, `.npmrc`, `.pypirc`,
  `.netrc` or any other credential store.
- Never edit `.ai-safe-workspace.json`, `ai-safe.yaml`, `.gitleaks.toml`, `.gitleaksignore`.
- Never try to recover sanitized values (no decoding, no searching history, no asking).
- Never print environment variables wholesale (`env`, `printenv`, `set`).
- Never run `git push`, `ai-safe integrate` or `ai-safe cleanup`. Integration is a
  developer-only step.

## 3. How to handle credentials in code

- Read configuration from environment variables or the project's secret manager:
  - Python: `os.environ["DB_PASSWORD"]`
  - Node: `process.env.DB_PASSWORD`
  - Go: `os.Getenv("DB_PASSWORD")`
- **Never hardcode** a password, key, token or connection string, not even a fake-looking one.
  Use an environment lookup and document the variable name.
- Leave existing placeholder lines (`${AI_SAFE_SECRET_...}`) unchanged unless the task is to
  replace the hardcoded credential with an environment lookup. Never copy a placeholder
  into new code and never replace a placeholder with a literal value.
- For tests, use obviously synthetic values generated at runtime or test fixtures that
  are clearly fake and not credential-shaped.

## 4. Missing configuration

If something needs a credential or config value that is not available, do not invent one.
Report it as a placeholder requirement:

```
Placeholder requirement:
  name:     PAYMENTS_API_KEY
  used by:  src/payments/client.py
  how:      read from environment variable PAYMENTS_API_KEY
  purpose:  authenticate to the payments provider
```

`AI_SAFE_PLACEHOLDERS.md` lists the placeholders that already exist.

## 5. After implementing

Run the security checks and report the results to the user:

```bash
ai-safe verify     # workspace still contains no secrets / keys / symlinks
ai-safe review     # AI changes: hardcoded credentials, placeholder misuse, sensitive files
```

If either command fails, fix the reported issues in the workspace (for example, replace a
hardcoded value with an environment lookup), then run both again. If the `ai-safe` command
is not available, follow section 6; do not skip the step silently.

Team skills, commands and agents you edit here (`.claude/skills/`, `.claude/commands/`,
`.claude/agents/`, other than the ai-safe skills) will be shown to the developer for review
before integration, because they steer future AI sessions in the original repository.

## 6. When `ai-safe` is not available

If `command -v ai-safe` fails, or `ai-safe verify` reports that no session was found (for
example inside Docker, or when ai-safe was installed locally in the original repository), the
checks can only run on the host. Then:

- Do not install ai-safe and do not search for it (no `pip install`, no looking for its
  installation directory, no reading paths outside this workspace).
- Finish the work, and in your hand-off give the developer these commands to run on the host,
  inside the workspace path: `ai-safe verify` and `ai-safe review`.

## Failure conditions: stop and tell the user

- No `.ai-safe-workspace.json` marker.
- You find something that looks like a real credential, private key or `.git` directory. Report its
  type and location only. Never repeat, use or copy the value. Recommend rotation and wait for the
  user's decision.
- A task requires access outside the workspace or to real credentials.
- `ai-safe verify` or `ai-safe review` reports CRITICAL issues you cannot fix inside the workspace.
