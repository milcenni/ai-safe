# ai-safe security model

## 1. Scope and goal

Goal: an AI coding agent must not receive real credentials or original Git history from a developer's
repository, and AI-written changes must be reviewed before they reach that repository.

ai-safe is a **risk-reduction tool**. It depends on pattern-based detection and on the operating
environment for isolation. It makes no claim that every secret is found.

## 2. Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Credential values (working tree) | Original repository | Never copied. Replaced by placeholders, or the file is excluded. |
| Credential values (history) | Original `.git` | `.git` is never copied. Values found only in history are also replaced if they reappear in a file. |
| Original Git objects and metadata | Original `.git` | Never copied. The verifier rejects `.git` directories, gitdir files and bare layouts. |
| Credential mapping | `~/.local/state/ai-safe/sessions/<id>/` (0700/0600) | Stores fingerprints and metadata only. Values are stored only on opt-in, encrypted with scrypt and Fernet. |
| Review baseline (snapshot) | State directory | Outside the workspace, so the AI cannot alter what it is compared against. |
| Original repository integrity | Developer machine | Integration only through review, validation, final scan and typed approval. Atomic writes. No commit or push. |

## 3. Adversaries and assumptions

- **A1: careless agent.** Hardcodes credentials, copies placeholders, edits `.env`, creates symlinks.
- **A2: prompt-injected or hostile agent.** Fully controls workspace contents and timing. Tries to read
  outside the workspace, plant files that weaken scanners (`.gitleaks.toml`, `.gitleaksignore`,
  `gitleaks:allow`), and smuggle data back into the original repository through symlinks, hard links, path
  traversal, binaries or CI and build files.
- **A3: local attacker.** Another user on the machine. Mitigated by 0700/0600 permissions and
  unpredictable temporary names.

Assumptions:

- The original repository and the developer's terminal are trusted.
- The ai-safe code and the Gitleaks binary are trusted.
- **The agent cannot read the original repository or the state directory.** This must be enforced by the OS
  (separate user, container, sandbox). ai-safe cannot enforce it for an agent that runs as the developer
  with unrestricted shell access.

## 4. Threats and controls

| # | Threat | Control | Tested by |
|---|---|---|---|
| T1 | A secret is copied into the workspace | Two detection engines. Exact-span redaction. Re-scan after redaction. Global replacement of known values. Final known-value sweep. Fail closed by excluding the file. Verifier with keyed-fingerprint token matching. | `test_sanitizer.py`, `test_verifier.py::test_known_secret_detected_without_any_pattern` |
| T2 | A secret appears in logs, terminal output, reports or errors | `Finding.secret` is excluded from `repr` and serialization. Output goes through a redacting stream. JSON is redacted. Error messages carry rule and line only. Gitleaks reports are written to a 0700 temp dir and shredded. | `test_scanner.py::test_cli_scan_never_prints_secret…`, `test_security.py::test_cli_start_end_to_end_output_has_no_secrets` |
| T3 | Git history is exposed | `.git` is in the mandatory exclusions. Verifier checks for Git metadata. The marker and settings contain no repository path. | `test_git_history.py::test_ai_cannot_reach_original_history_from_workspace`, `test_verifier.py::test_detects_git_metadata` |
| T4 | Repository-controlled code runs during a scan | `core.hooksPath=/dev/null`, `--no-ext-diff --no-textconv`, `diff.external=`, `core.fsmonitor=false`, `protocol.allow=never`. Dangerous `GIT_*` environment variables are dropped. No shell. | `test_git_history.py::test_scan_does_not_execute_repo_controlled_git_drivers` |
| T5 | Detection is weakened by planted scanner config | Gitleaks always runs with `--config <ai-safe config>`, an empty `--gitleaks-ignore-path`, and `--ignore-gitleaks-allow`. Changes to `ai-safe.yaml`, `.gitleaks.toml` and `.gitleaksignore` are blocked in review. | `test_verifier.py::test_gitleaks_verification_ignores_planted_allowlists` |
| T6 | Writes escape the repository through symlinks or traversal | `safe_relpath` rejects absolute paths, `..`, backslashes and control characters. `safe_join` rejects symlinked components. Targets are validated twice (before approval and right before writing). | `test_integration.py::test_path_traversal_and_symlink_targets_rejected`, `test_security.py::test_safe_join…` |
| T7 | The AI reads outside the workspace through symlinks, hard links or directory swaps | Verifier and review flag every symlink (CRITICAL if it escapes) and every hard link. The workspace is walked openat-style (`walk_nofollow`): a directory fd per level, `O_NOFOLLOW` on every component, inode re-check. Content is captured once and only those bytes are integrated. | `test_verifier.py::test_detects_symlink_escaping_workspace`, `test_integration.py::test_hard_link_rejected`, `test_review_findings.py::test_walk_never_reads_through_swapped_directory` |
| T8 | The AI modifies `.env`, credential stores or security config | Exclusion patterns and security-tool files are blocking review errors. The integration validator also refuses them. | `test_integration.py::test_ai_attempting_to_modify_env`, `test_security_config_and_marker_tampering` |
| T9 | The AI introduces hardcoded credentials | Built-in rules, Gitleaks on changed files, known-value fingerprints. A final scan of post-integration content blocks any credential not already in the original. | `test_integration.py::test_secret_introduced_by_ai_is_blocked`, `test_blocking_review_prevents_integration` |
| T10 | Placeholder misuse | Unknown placeholders, placeholders in AI-written lines, and placeholders replaced by literals are blocking. Credentials are never restored into AI lines; such hunks become conflicts. | `test_placeholder_incorrectly_replaced`, `test_placeholder_copied_into_new_code`, `test_unknown_placeholder`, `test_conflict_when_ai_edits_credential_line…` |
| T11 | Original credentials are lost or overwritten | Hunks are mapped through a snapshot-to-original alignment, so unchanged credential lines are preserved byte for byte. Excluded files are never written. A changed original aborts. | `test_integration.py::test_integration_preserves_original_credentials`, `test_original_changed_since_sanitize_aborts` |
| T12 | The agent integrates its own work | Integration requires typed approval, refuses agent environments (`CLAUDECODE`, …), refuses to run from the workspace, and refuses never-verified sessions. Claude settings deny `ai-safe integrate`. | `test_integrate_refuses_inside_ai_agent`, `test_integrate_refuses_from_workspace`, `test_integrate_refuses_unverified_workspace` |
| T13 | Unexpected commit or push | Not implemented anywhere; the config rejects `auto_commit` and `auto_push`. | `test_integration_preserves_original_credentials` (HEAD and index unchanged), `test_config_validation_rejects_unsafe` |
| T14 | Leftover workspaces or mappings | `cleanup` deletes only verified ai-safe directories, never follows symlinks, and shreds state files. A failed `start` deletes the workspace. | `test_security.py::test_cleanup_*`, `test_start_fails_closed_and_removes_workspace` |
| T15 | A weakened configuration | Pydantic with `extra="forbid"`. Unsafe values (`auto_push`, `include_git_history`, `fail_closed: false`, …) are rejected. `history_log_opts` is restricted to a safe character set. `sanitization.include_ignored_files: true` is rejected unless `scanner.scan_ignored: true` (ignored files would otherwise be copied unscanned). `security.docker_image` is restricted to an image-reference character set and cannot start with `-`. | `test_security.py::test_config_validation_rejects_unsafe` |
| T16 | Temporary names or files leak secrets | `mkdtemp` with fixed, validated prefixes. Files 0600, directories 0700. `O_EXCL`/`O_NOFOLLOW` when creating files. | `test_security.py::test_temp_names_never_contain_secrets`, `test_secure_tempdir_and_private_files` |
| T17 | AI-planted files that are invisible to `git status` (for example `.venv/…/x.pth`) | New files in paths the original repository ignores, or under tool directories, are blocking. | `test_review_findings.py::test_new_file_in_ignored_directory_rejected` |
| T18 | Approval-display spoofing (ANSI escapes, bidi "Trojan Source") | Untrusted text is escaped by `safe_display`. AI lines containing control or bidi characters are blocking. | `test_review_findings.py::test_ansi_and_bidi_blocked_and_escaped` |
| T19 | Weakened ignore rules exposing secrets to `git add` | Removed `.gitignore` rules, negations or a deleted `.gitignore` are blocking. | `test_review_findings.py::test_gitignore_weakening_blocked` |
| T20 | A secret leaks through placeholder names | Keys inside URLs are never used. Random-looking keys are rejected. Every name is cross-checked against all detected values. | `test_review_findings.py::test_url_username_token_not_used_as_placeholder_name` |

No network access is used for scanning or sanitization, and there is no telemetry.

## 5. Known limitations

See README "Security limitations". In short:

- Pattern-based detection can miss secrets that have no recognizable shape or key.
- OS-level isolation is the operator's responsibility.
- Secure deletion is best effort.
- Merge-commit diffs are not inspected by the built-in history scan.
- Short values are replaced only where they were detected.

## 6. Security review (implementation phase)

See [docs/TEST_REPORT.md](docs/TEST_REPORT.md) for the test run and the results of the independent
adversarial review performed after implementation.

## 7. Reporting

Report vulnerabilities privately to the maintainers. Do not include real credentials in reports or
reproductions; use synthetic values.
