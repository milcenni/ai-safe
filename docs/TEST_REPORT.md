# Test execution report

Date: 2026-11-19 · Environment: Linux (WSL2), Python 3.11.15, Git 2.25.1, Gitleaks 8.21.2
(official release, SHA-256 checked against the published checksums file).

All credentials used in tests are **synthetic**: random credential-shaped strings generated at runtime.
No real credentials were used.

## Result

```
pytest -q
154 passed in 22.6s   (0 failed, 0 errors, 0 skipped; Gitleaks tests included)
```

| Test file | Tests | Focus |
|---|---|---|
| `test_scanner.py` | 19 | Discovery across all locations, categories, false-positive guard, CLI output, Gitleaks engine and report import |
| `test_sanitizer.py` | 20 | Placeholders, exclusions, fail-closed redaction, manifest and mapping, encryption, permissions, original unchanged |
| `test_verifier.py` | 11 | Secrets, keys, symlinks, Git metadata, binaries, known-value fingerprints, planted Gitleaks allowlists |
| `test_git_history.py` | 6 | Diff parsing, deleted files, every ref, no repo-controlled drivers executed, sanitized summary |
| `test_integration.py` | 25 | Review checks, patch-based integration, credential preservation, refusals, end-to-end CLI |
| `test_security.py` | 44 | Path validation, temp files, redaction, config validation, cleanup, `start` fail-closed, skills |
| `test_review_findings.py` | 29 | Regression tests for every issue found in the independent security review |

## Required scenarios (spec §10)

| Scenario | Test(s) |
|---|---|
| API key in Python source | `test_scanner::test_api_key_in_python_source`, `test_sanitizer::test_api_key_replaced_with_deterministic_placeholder` |
| Database password in `.env` | `test_scanner::test_database_password_in_env_is_found_as_ignored`, `test_sanitizer::test_env_files_keys_and_credential_stores_excluded` |
| AWS-style access credentials | `test_scanner::test_aws_credentials`, `test_sanitizer::test_yaml_and_json_credentials` |
| SSH private key | `test_scanner::test_ssh_private_key_detected`, `test_sanitizer::test_ssh_private_key_file_excluded_and_embedded_key_redacted` |
| Password in YAML | `test_scanner::test_password_in_yaml_and_json`, `test_sanitizer::test_yaml_and_json_credentials`, `test_yaml_block_scalar_secret` |
| Credentials in JSON | same as above |
| Secret in an untracked file | `test_scanner::test_secret_in_untracked_file` |
| Secret in a staged change | `test_scanner::test_secret_in_staged_change` |
| Secret in an unstaged change | `test_scanner::test_secret_in_unstaged_change` |
| Secret in a previous commit | `test_scanner::test_secret_in_previous_commit_and_removed_from_head`, `test_history_covers_all_branches_and_tags` |
| Secret removed from the latest commit but kept in history | same, plus `test_sanitizer::test_history_only_secret_replaced_if_it_reappears` |
| Secret introduced by AI | `test_integration::test_secret_introduced_by_ai_is_blocked`, `test_blocking_review_prevents_integration` |
| Placeholder incorrectly replaced | `test_integration::test_placeholder_incorrectly_replaced`, `test_placeholder_copied_into_new_code`, `test_unknown_placeholder` |
| Symlink pointing outside the workspace | `test_verifier::test_detects_symlink_escaping_workspace`, `test_sanitizer::test_binary_and_symlink_handling` |
| Path traversal attack | `test_integration::test_path_traversal_and_symlink_targets_rejected`, `test_security::test_safe_relpath_rejects` |
| AI attempting to modify `.env` | `test_integration::test_ai_attempting_to_modify_env` |
| AI attempting to access the original Git history | `test_git_history::test_ai_cannot_reach_original_history_from_workspace`, `test_integration::test_symlink_created_by_ai`, `test_verifier::test_detects_git_metadata` |
| Sanitization failure | `test_sanitizer::test_sanitization_failure_excludes_file`, `test_redaction_engine_fails_when_secret_not_locatable`, `test_store_values_without_passphrase_fails_closed` |
| Integration preserving original credentials | `test_integration::test_integration_preserves_original_credentials`, `test_removing_hardcoded_credential_is_applied_with_warning` |
| Cleanup of temporary workspaces | `test_security::test_cleanup_removes_workspace_and_state`, `test_cleanup_refuses_foreign_directories`, `test_cli_cleanup`, `test_start_fails_closed_and_removes_workspace` |

## Manual end-to-end verification

On a synthetic demo repository (`examples/make_demo_repo.py`), the full CLI run was
`start` → AI edit → `verify` → `review` → `integrate` (typed `apply`) → `cleanup`:

- `start` found 8 unique secrets: 7 in history, one of which exists only in history. It excluded the
  `id_rsa` file, and verification passed.
- A search of the workspace for every synthetic value found 0 occurrences.
- After integration, `git diff` showed only the AI's change. The hardcoded key was replaced by an env
  lookup, every other credential line was unchanged, and nothing was committed.
- `cleanup` removed both the workspace and the session state.

The original repository and its credentials were unchanged by `scan`, `sanitize`, `verify` and `review`
(`test_sanitizer::test_original_repository_unchanged`, `test_git_history::test_scan_never_modifies_git_state`).

## Independent security review

After implementation, a separate reviewer, given the code and the threat model but not the author's
conclusions, attacked the tool with proof-of-concept scripts. It found 7 verified issues and 1 unverified
issue. All of them are fixed, and each has a regression test in `test_review_findings.py`. The reviewer's
PoCs were re-run against the fixed code and no longer succeed.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | Directory-swap race: swapping an intermediate workspace directory for a symlink during review let an outside file's content be integrated (`O_NOFOLLOW` only covers the last component) | New `security.walk_nofollow`: an openat-style walk holding a directory fd per level, `O_NOFOLLOW` on every component, inode re-check. File bytes are captured once and used for scanning, planning and writing. The PoC now integrates the genuine workspace content. |
| 2 | High | A token used as a URL username became the placeholder *name* and was stored as `key` in `credential-map.json` | No key derivation inside URLs. Random-looking keys are rejected. Placeholder names and keys are cross-checked against all detected values (case- and separator-insensitive) and renamed if needed. New rule `url-username-token`. |
| 3 | High | Detector gaps: verification passed with real secrets in about 13 common forms | New rules: URL with empty user or short password, INI `#`/`;` inside values, `$(` inside literals, `mysql -p`, `sshpass -p`, `curl -u`, `--password`, `Basic` headers, query-string and connection-string passwords, Dockerfile `ENV K V`, heredocs, `put("password", …)`, `HTTPBasicAuth(…)`, credential tuples, wrapper calls (`[]byte(…)`, `new String(…)`), env-var defaults, passwords in comments, `*.env.example` files. All 26 PoC forms are now redacted. |
| 4 | Medium | Integration wrote new files into git-ignored directories such as `.venv/…/x.pth` (code execution, invisible to `git status`) | New files in paths ignored by the original repository (`git check-ignore`) or under tool directories are blocking. |
| 5 | Medium | `.gitignore` changes were not flagged, so emptying it exposed `.env` to `git add` | Ignore files are flagged as sensitive config. Removed rules, negations or deletion are blocking. |
| 6 | Medium | ANSI escape sequences in AI content could hide code in the approval patch | `safe_display` escapes C0/C1 and bidi characters in all displayed untrusted text. AI lines containing them are blocking (`hidden-characters`). |
| 7 | Medium/Low | Deletions skipped the "original changed" check | Deletions verify the keyed digest at review time and again right before unlinking. |
| 8 | Low (unverified) | `history_log_opts` could pass `--output=` (git also accepts abbreviations) | Strict allowlist of git-log options and revision tokens. |

Hardening added before the review: hard-link detection, a re-hash of content against the change list, and
integration refusing sessions that never passed verification.

## Residual risks

Pattern-based detection is inherently incomplete. Secrets with no recognizable key or format, encoded or
split values, and secrets inside binaries can still be missed. Integration still depends on OS-level
isolation of the agent. See README "Security limitations".
