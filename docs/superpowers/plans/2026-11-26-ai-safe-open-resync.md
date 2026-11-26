# ai-safe open / resync / team .claude Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ai-safe open` and `ai-safe resync`, carry the team's Claude Code skills, commands and agents safely into and back out of the workspace, tighten config validation, and update the docs and skills as agreed.

**Architecture:** There are two new modules, `launcher.py` (`open`) and `resync.py` (`resync`), and both reuse the existing scan → sanitize → verify pipeline. A single classifier helper, `claude_path_policy`, decides how every `.claude/` path is treated. The sanitizer, scanner, verifier, review and integration all ask that helper instead of hard-coding `.claude/`. Every new command that reads the original repository refuses to run inside an AI agent session, the same way `integrate` does.

**Tech Stack:** Python 3.11+, typer, pydantic v2, pytest. Tests use `CliRunner` and the fixtures in `tests/conftest.py`.

**Spec:** The decisions agreed with the user in conversation on 2026-11-26 are recorded in the "Decisions" section below. The source request is `.claude/AI_SAFE_UPDATE_INSTRUCTIONS.md`, as corrected by those decisions.

## Decisions (the spec)

1. **Who runs what.** The AI never runs `ai-safe start`, `scan`, `resync`, `integrate` or `cleanup` in a user's repository. When the user asks for implementation work in the main project, the AI tells them to run `ai-safe start` and then `ai-safe open` themselves. Inside the workspace the AI works freely.
2. **`ai-safe open`.**
   - It shows a menu: (1) AI agent CLI (`security.launch_command`), (2) VSCode (`code -n <ws>`), (3) Docker, (4) print the commands only.
   - It respects `security.allow_ai_launch`. When that is false, it only prints the commands.
   - It refuses inside an AI agent session. Without a TTY it prints the commands and exits 2.
   - Docker: if `security.docker_image` is set and `docker` is on PATH, it tries to run the container. If the image is unset or the run fails, it prints an example command.
   - The workspace location comes from the existing state directory. Nothing is written into the main project.
3. **`ai-safe resync`.**
   - The workspace keeps the same path and directory inode.
   - It builds a new workspace in a staging directory and verifies it there, then replaces the workspace contents in place. If anything fails, the old workspace and the session state are left untouched.
   - It is allowed without `--discard` only when the workspace has no changes since the snapshot, or when the workspace is byte-identical to what was last integrated. Otherwise it needs `--discard` plus the typed word `discard`.
   - It refuses inside an AI agent session.
4. **Config.**
   - Reject `scanner.scan_ignored: false` together with `sanitization.include_ignored_files: true`.
   - The AI asks the user before changing `scan_ignored`, and never opens ignored files to decide.
5. **`.claude/` policy.**
   - Not scanned and not copied: `.ai-safe/` and `.claude/ai-safe/`.
   - ai-safe's own skills (`.claude/skills/<SKILL_NAMES>/…`) are never copied; the workspace regenerates them from templates. They are skipped by the scanner only when byte-identical to the current template, so they cause no false positives.
   - The team's `.claude/skills|commands|agents/**` are scanned, redacted and copied.
   - `.claude/settings.json` is merged into the generated settings, and ai-safe's deny rules always win.
   - Every other `.claude/` path stays excluded. That includes `settings.local*.json`.
6. **Integration of `.claude/`.**
   - The team's `.claude/skills|commands|agents/**` (not ai-safe skills) are integrated. Each such change always carries a WARNING `agent-instructions` and appears in the approval diff.
   - `.claude/settings.json`, ai-safe skills and other `.claude/` paths are never integrated.
   - Any workspace change under `.ai-safe/` or `.claude/ai-safe/` is a blocking ERROR.
7. **Tool availability.** In Docker, or with a local install, the AI cannot run `ai-safe`. The skill tells it not to install ai-safe and to ask the user to run `ai-safe verify` / `ai-safe review` on the host.
8. **Docs.** Update README (Quick Start), AGENTS.md (git init before a local install, new §5 on open/resync, `scan_ignored` consent, AI-launch wording) and SECURITY.md. Recommend a `.gitignore` that covers only `.ai-safe/` and `.claude/settings.local*.json`.

## Global Constraints

- Fail closed. Any error leaves the original repository, the existing workspace and the session state unchanged.
- Never put secret values in messages, logs, reports or exceptions. Error text carries a path or a rule id only.
- Tests use synthetic credentials from `tests/conftest.py::Fake` only. Never write a literal credential-shaped string into source, docs or skills.
- `skills/<name>/SKILL.md` must stay byte-identical to `src/ai_safe/skill_templates/<name>/SKILL.md`.
- Never add automatic commit, push or AI launch. `open` launches only when a human picks a menu option and `allow_ai_launch` is true.
- Every security change gets a regression test and a row (or row update) in `SECURITY.md`.
- Exit codes: 0 OK, 1 security check failed, 2 usage/config, 3 operational error.
- Run the full suite with `.venv/bin/pytest -q`. The baseline is 154 passed.

## Review Focus

1. **Resync while the AI session is open.** Files must never exist in the live workspace before they have been verified. Test: `test_resync_verification_failure_leaves_workspace_untouched`.
2. **The AI plants files in install directories.** An AI writing `.ai-safe/bin/ai-safe` or `.claude/ai-safe/x` in the workspace must block integration, because otherwise it would replace the user's ai-safe binary. Test: `test_ai_safe_install_dir_change_blocks` (Task 4).
3. **A credential inside a team skill or command.** It must be redacted in the workspace exactly like any other file. Test: `test_team_skill_secret_redacted` (Task 3).
4. **Team `settings.json` with `hooks`, `env`, `apiKeyHelper` or `permissions.additionalDirectories`.** These keys must not reach the workspace, because they can run code or point at the original repository. Test: `test_merge_settings_drops_dangerous_keys` (Task 3).
5. **Integrate with `--exclude`, then resync.** Excluded changes must not be silently discarded. Test: `test_resync_after_partial_integration_requires_discard` (Task 5).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/ai_safe/config.py` (modify) | Cross-field validator, `security.docker_image`, `MANDATORY_EXCLUDES` adds `.claude/ai-safe/`, default YAML |
| `src/ai_safe/classifier.py` (modify) | `ClaudePath` enum, `claude_path_policy()`, `sensitive_match()` |
| `src/ai_safe/scanner.py` (modify) | Skip install dirs and pristine ai-safe skills (list_files + gitleaks results) |
| `src/ai_safe/workspace.py` (modify) | `merge_claude_settings()`, `install_claude_integration(..., team_settings)`, `Session.integrated_tree_hash`, `replace_tree_contents()` |
| `src/ai_safe/sanitizer.py` (modify) | Copy team `.claude` files, collect and merge team settings |
| `src/ai_safe/verifier.py` (modify) | Allow team `.claude` paths; still scan them |
| `src/ai_safe/review.py` (modify) | Integrate team `.claude` paths with a WARNING; block install dirs |
| `src/ai_safe/integration.py` (modify) | Use `sensitive_match`; record `integrated_tree_hash` |
| `src/ai_safe/resync.py` (create) | `pending_changes()`, `resync()` |
| `src/ai_safe/launcher.py` (create) | `LaunchOption`, `launch_options()`, `run_option()` |
| `src/ai_safe/cli.py` (modify) | `resync` and `open` commands |
| `tests/test_claude_team.py` (create) | Tasks 2–4 |
| `tests/test_resync.py` (create) | Task 5 |
| `tests/test_launcher.py` (create) | Task 6 |
| Docs and skills (modify) | Task 7 |

---

### Task 1: Config validation and `docker_image`

**Files:**
- Modify: `src/ai_safe/config.py` (`SecurityConfig`, `AISafeConfig`, `MANDATORY_EXCLUDES`, `DEFAULT_CONFIG_YAML`)
- Modify: `ai-safe.yaml`
- Test: `tests/test_security.py`

**Interfaces:**
- Produces: `SecurityConfig.docker_image: str | None = None`; `AISafeConfig` validator that rejects the combination; `MANDATORY_EXCLUDES` containing `".claude/ai-safe/"`.

- [ ] **Step 1: Write the failing tests.** Add to the `test_config_validation_rejects_unsafe` parametrize list:

```python
({"scanner": {"scan_ignored": False}, "sanitization": {"include_ignored_files": True}}, "include_ignored_files"),
({"security": {"docker_image": "bad image;rm"}}, "docker_image"),
```

Add a new test:

```python
def test_docker_image_and_install_excludes():
    cfg = parse_config({"version": 1, "security": {"docker_image": "ghcr.io/acme/claude:1.2"}})
    assert cfg.security.docker_image == "ghcr.io/acme/claude:1.2"
    assert ".claude/ai-safe/" in cfg.sanitization.all_excludes()
    assert ".ai-safe/" in cfg.sanitization.all_excludes()
```

- [ ] **Step 2: Run them and confirm they fail.** Run `.venv/bin/pytest tests/test_security.py -q -k "config_validation or docker_image"`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `docker_image` is validated with `re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", v)`.
  - Add an `AISafeConfig` `model_validator(mode="after")` that raises `"sanitization.include_ignored_files=true requires scanner.scan_ignored=true (ignored files would be copied unscanned)"`.
  - Append `".claude/ai-safe/"` to `MANDATORY_EXCLUDES`. Keep `".claude/"` there; Task 2 carves out the team paths.
  - Add `# docker_image: ghcr.io/you/claude-code:tag` under `security:` in both `DEFAULT_CONFIG_YAML` and `ai-safe.yaml`, with a comment above `scan_ignored` saying that false means ignored files are not scanned.
- [ ] **Step 4: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "feat(config): reject unscanned ignored files, add security.docker_image"`

---

### Task 2: `.claude/` path policy and scanner skips

**Files:**
- Modify: `src/ai_safe/classifier.py`, `src/ai_safe/scanner.py`
- Test: `tests/test_claude_team.py` (create)

**Interfaces:**
- Consumes: `SKILL_NAMES`, `skill_template(name)` from `ai_safe.workspace`. Import them lazily inside the function to avoid an import cycle.
- Produces:
  - `class ClaudePath(Enum)` with the members `NONE`, `INSTALL`, `AI_SAFE_SKILL`, `TEAM`, `SETTINGS`, `OTHER`.
  - `claude_path_policy(rel: str) -> ClaudePath`.
  - `sensitive_match(rel: str, excludes: list[str]) -> str | None`. It behaves like `match_exclude`, except that for `TEAM` and `SETTINGS` paths it ignores the single `".claude/"` pattern. Every other pattern, such as `.env`, still applies.
  - `is_pristine_ai_safe_skill(root: Path, rel: str) -> bool`.

Policy table (paths are case-folded):

| Path | Result |
|---|---|
| starts with `.ai-safe/` or `.claude/ai-safe/` | `INSTALL` |
| `.claude/skills/<n>/…` where `<n>` is in `SKILL_NAMES` | `AI_SAFE_SKILL` |
| `.claude/skills/…`, `.claude/commands/…`, `.claude/agents/…` | `TEAM` |
| exactly `.claude/settings.json` | `SETTINGS` |
| any other `.claude/…` | `OTHER` |
| anything else | `NONE` |

- [ ] **Step 1: Write the failing tests** in `tests/test_claude_team.py`:

```python
@pytest.mark.parametrize("rel,expected", [
    (".ai-safe/bin/ai-safe", ClaudePath.INSTALL), (".claude/ai-safe/x", ClaudePath.INSTALL),
    (".claude/skills/ai-safe/SKILL.md", ClaudePath.AI_SAFE_SKILL),
    (".claude/skills/ai-safe-review/extra.md", ClaudePath.AI_SAFE_SKILL),
    (".claude/skills/deploy/SKILL.md", ClaudePath.TEAM), (".claude/commands/x.md", ClaudePath.TEAM),
    (".claude/agents/r.md", ClaudePath.TEAM), (".claude/settings.json", ClaudePath.SETTINGS),
    (".claude/settings.local.json", ClaudePath.OTHER), (".claude/hooks/h.sh", ClaudePath.OTHER),
    ("app/x.py", ClaudePath.NONE),
])
def test_claude_path_policy(rel, expected): ...

def test_sensitive_match_carves_out_team_only():
    ex = AISafeConfig().sanitization.all_excludes()
    assert sensitive_match(".claude/skills/deploy/SKILL.md", ex) is None
    assert sensitive_match(".claude/skills/deploy/.env", ex) is not None
    assert sensitive_match(".claude/settings.local.json", ex) == ".claude/"

def test_scanner_skips_install_dirs_and_pristine_skills(make_repo, fake):
    # repo tracks .ai-safe/lib.py and .claude/ai-safe/x.txt, each holding fake.github();
    # .claude/skills/ai-safe/SKILL.md = skill_template("ai-safe")
    # .claude/skills/ai-safe-scan/SKILL.md = template + f"\nTOKEN = \"{fake.github()}\"\n"
    # -> the findings' files == {".claude/skills/ai-safe-scan/SKILL.md"}
```

- [ ] **Step 2: Run them and confirm they fail.** Run `.venv/bin/pytest tests/test_claude_team.py -q`. Expected: ImportError.
- [ ] **Step 3: Implement** the policy, `sensitive_match` and `is_pristine_ai_safe_skill`. The last one compares bytes with `skill_template(name)` for the `SKILL.md` file. Any other file under an ai-safe skill directory is not pristine.
- [ ] **Step 4: Change the scanner.** In `Scanner`, add `_skip(root, rel) -> bool`, which returns True for `INSTALL` paths or pristine ai-safe skills. Apply it in `list_files` (drop those entries) and in the gitleaks loop in `scan()` (`continue` when `_skip(root, rel)`).
- [ ] **Step 5: Run the tests.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 6: Commit.** `git commit -m "feat: .claude path policy; scanner skips ai-safe install dirs and pristine skills"`

---

### Task 3: Copy team `.claude` files and merge settings into the workspace

**Files:**
- Modify: `src/ai_safe/workspace.py`, `src/ai_safe/sanitizer.py`, `src/ai_safe/verifier.py`
- Test: `tests/test_claude_team.py`, and update `tests/test_sanitizer.py:60-75` if its expectations change.

**Interfaces:**
- Consumes: `claude_path_policy`, `sensitive_match` (Task 2).
- Produces:
  - `merge_claude_settings(team: dict | None, generated: dict) -> dict` in `workspace.py`.
  - `install_claude_integration(ws, state_root_path, cfg, team_settings: dict | None = None)`.

Merge rules:
- Start from a deep copy of `team`.
- Drop the top-level keys `hooks`, `env`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine` and `enabledMcpjsonServers`, plus `permissions.additionalDirectories`.
- Set `permissions.deny` = team deny + generated deny, de-duplicated, in that order.
- Remove from `permissions.allow` and `permissions.ask` every entry that is also in the generated deny list.
- Set `_comment` to the generated comment.
- If `team` is None or not a dict, return `generated` unchanged.

- [ ] **Step 1: Write the failing tests.**

```python
def test_merge_settings_drops_dangerous_keys():
    gen = claude_settings(Path("/tmp/state"))
    team = {"hooks": {"PreToolUse": []}, "env": {"X": "1"}, "apiKeyHelper": "x",
            "permissions": {"allow": ["Bash(git push:*)", "Bash(npm test)"], "deny": ["Read(./secret)"],
                            "additionalDirectories": ["../orig"]}, "model": "opus"}
    m = merge_claude_settings(team, gen)
    assert not {"hooks", "env", "apiKeyHelper"} & m.keys()
    assert "additionalDirectories" not in m["permissions"]
    assert m["permissions"]["allow"] == ["Bash(npm test)"]
    assert m["permissions"]["deny"][0] == "Read(./secret)" and set(gen["permissions"]["deny"]) <= set(m["permissions"]["deny"])
    assert m["model"] == "opus"

def test_team_claude_files_copied_and_settings_merged(make_repo):
    # repo: .claude/skills/deploy/SKILL.md, .claude/commands/t.md, .claude/agents/a.md,
    #       .claude/settings.json {"permissions":{"allow":["Bash(npm test)"]},"hooks":{}},
    #       .claude/settings.local.json "{}", .claude/hooks/h.sh "echo"
    # -> the three team files exist in p.ws with identical text; p.verification.passed
    # -> settings.local.json and hooks/h.sh are absent; ws settings has "Bash(npm test)" in allow and no "hooks"

def test_team_skill_secret_redacted(make_repo, fake):
    # .claude/commands/deploy.md contains f'API_KEY = "{fake.openai()}"'
    # -> the raw value is not in p.ws/.claude/commands/deploy.md, "${AI_SAFE_SECRET_" is in it, p.verification.passed

def test_invalid_team_settings_json_excluded(make_repo):
    # .claude/settings.json = "{not json" -> the ws settings equal claude_settings(...) exactly; manifest reason mentions "invalid JSON"
```

- [ ] **Step 2: Run them and confirm they fail.** Run `.venv/bin/pytest tests/test_claude_team.py -q`.
- [ ] **Step 3: Implement the merge in `workspace.py`.** Add `merge_claude_settings` and the `team_settings` parameter. When the parameter is given, write `merge_claude_settings(team_settings, claude_settings(...))`.
- [ ] **Step 4: Change `Sanitizer._process`.**
  - Replace `match_exclude(rel, self.excludes)` with `sensitive_match(rel, self.excludes)`.
  - Before the `generated_paths()` check, handle `SETTINGS`: redact the text through the normal path, then `json.loads` it into `self._team_settings`. On failure, return an excluded entry with the reason `"invalid JSON in .claude/settings.json (not merged)"`. On success, return `ManifestEntry(rel, "merged", "merged into generated .claude/settings.json")` and do not write the file at that point.
  - In `run()`, pass `self._team_settings` (initialised to `None`) to `install_claude_integration`.
- [ ] **Step 5: Change the verifier** (`verifier.py:159-165`): the branch becomes `elif rel.startswith(".claude/") and claude_path_policy(rel) is not ClaudePath.TEAM:`, keeping the existing body, so team files fall through to the normal checks and scanning. Replace `match_exclude` with `sensitive_match`.
- [ ] **Step 6: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 7: Commit.** `git commit -m "feat: copy team Claude skills/commands/agents into workspace; merge settings with ai-safe deny rules"`

---

### Task 4: Review and integration of team `.claude` changes

**Files:**
- Modify: `src/ai_safe/review.py` (`_is_tool_metadata`, `review_session` loop), `src/ai_safe/integration.py` (`_validate_targets`, end of `integrate`), `src/ai_safe/workspace.py` (`Session`)
- Test: `tests/test_claude_team.py`. The existing `tests/test_integration.py::test_nested_git_and_claude_metadata_not_integrated` must still pass unchanged.

**Interfaces:**
- Produces: `Session.integrated_tree_hash: str | None = None`. It is set to `tree_hash(session.workspace_path)` after a successful apply, only when `exclude_paths == ()`. Task 5 reads it.

- [ ] **Step 1: Write the failing tests.**

```python
def test_team_skill_change_integrated_with_warning(team_project):   # fixture: Task 3 repo prepared
    # AI edits ws/.claude/skills/deploy/SKILL.md
    rr = review(team_project)
    assert rr.passed and ".claude/skills/deploy/SKILL.md" in [p.path for p in rr.plan]
    assert any(i.code == "agent-instructions" and i.severity is Severity.WARNING for i in rr.issues)
    res = integrate(team_project.session, team_project.cfg, team_project.scanner, confirm=APPROVE)
    assert ".claude/skills/deploy/SKILL.md" in res.applied

def test_settings_and_ai_safe_skill_changes_never_integrated(team_project):
    # AI edits ws/.claude/settings.json and ws/.claude/skills/ai-safe/SKILL.md
    # -> neither path is in the plan; both appear in rr.skipped

def test_ai_safe_install_dir_change_blocks(team_project):
    # AI writes ws/.ai-safe/bin/ai-safe and ws/.claude/ai-safe/x
    # -> not rr.passed; "ai-safe-install" in blocking_codes(rr)

def test_integrated_tree_hash_recorded_only_without_exclude(team_project): ...
```

- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Change `review.py`.**
  - Policy `INSTALL` → `report.add(Severity.ERROR, "ai-safe-install", path, "change inside an ai-safe installation directory is never allowed")`, then `continue`. This check goes before `_is_tool_metadata`.
  - `_is_tool_metadata(path)` is True for `generated_paths()` and for the policies `AI_SAFE_SKILL`, `SETTINGS` and `OTHER`.
  - For `TEAM` paths, add `Severity.WARNING, "agent-instructions", path, "AI changed Claude Code skills/commands/agents - these steer future AI sessions in the original repository; read the full diff"`, then continue through the normal checks.
  - Replace `match_exclude` with `sensitive_match`.
- [ ] **Step 4: Change `integration.py`.** `_validate_targets` uses `sensitive_match`. After `session.status = "integrated"`, set `session.integrated_tree_hash = tree_hash(session.workspace_path) if not exclude_paths else None`.
- [ ] **Step 5: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 6: Commit.** `git commit -m "feat: integrate team Claude skills/commands/agents with mandatory review warning; block install dirs"`

---

### Task 5: `ai-safe resync`

**Files:**
- Create: `src/ai_safe/resync.py`
- Modify: `src/ai_safe/workspace.py` (add `replace_tree_contents`), `src/ai_safe/cli.py` (add the `resync` command)
- Test: `tests/test_resync.py`

**Interfaces:**
- Consumes: `Session.integrated_tree_hash` (Task 4), `Sanitizer`, `verify_workspace`, `collect_changes`, `tree_hash`, `secure_mkdtemp`, `write_marker`, `detect_ai_agent_env`.
- Produces:
  - `pending_changes(session: Session) -> list[FileChange]`: the changes from snapshot to workspace. Returns `[]` when `tree_hash(ws) == session.integrated_tree_hash`.
  - `@dataclass ResyncResult(ok: bool, reason: str | None, verification: VerificationReport | None)`.
  - `resync(session, cfg, store, scanner, salt, *, discard: bool, passphrase: str | None) -> ResyncResult`. It raises `SecurityError` when an agent is detected. It returns `ResyncResult(False, "workspace has changes not integrated - run ai-safe integrate, or resync --discard", None)` when changes are pending and `discard` is False.
  - `replace_tree_contents(dst: Path, src: Path) -> None`: removes every entry inside `dst` (not following symlinks), then `os.rename`s every entry of `src` into `dst`. `dst` itself is never removed or recreated. `src` must be on the same filesystem; on `OSError` (EXDEV) it raises `SecurityError`.

Algorithm for `resync()`, after the guards:
1. Scan `session.repo_path`.
2. Create a staging workspace with `secure_mkdtemp(WORKSPACE_PREFIX, ws.parent)` and a staging state directory `store.sessions_dir / f"{session.id}.resync"` (0700). The state root is still `state_dir.parent.parent`.
3. Build `staging = Session(id=session.id, repo=session.repo, workspace=str(stage_ws), state_dir=str(stage_state), created_at=session.created_at)` and call `write_marker(stage_ws, session.id)`.
4. Run `Sanitizer(cfg, scanner, salt).run(scan, staging, passphrase=passphrase)`, then `verify_workspace(stage_ws, …, fingerprints=CredentialMap.load(stage_state).fingerprints())`.
5. If verification fails, remove both staging directories and return `ResyncResult(False, "verification failed", vr)`.
6. On success:
   - `replace_tree_contents(ws, stage_ws)`.
   - Move `manifest.json`, `credential-map.json`, `credential-secrets.enc` (if present) and `snapshot/` from the staging state into the session state, removing the old ones first.
   - Set `session.status = "verified"`, `session.verified_tree_hash = tree_hash(ws)` and `session.integrated_tree_hash = None`, then call `session.save()`.
   - Remove the staging directories.
7. Wrap steps 2–6 in a `try/finally` that always removes the staging directories.

CLI:
- `ai-safe resync [--session/-s] [--config/-c] [--discard]`.
- It prints "Close any AI session in the workspace before resyncing."
- With `--discard` and pending changes, it asks `typer.prompt("Type 'discard' to throw away N uncommitted workspace change(s)")` and aborts with exit 1 unless the answer is exactly `discard`.
- Success prints "Workspace resynced (same path)", the workspace path, and exits 0. `ok=False` → exit 1.

- [ ] **Step 1: Write the failing tests** in `tests/test_resync.py`, using the `project` fixture pattern from `test_integration.py`:

```python
def test_resync_clean_workspace_picks_up_original_changes(project): # edit repo app/util.py -> resync ok -> ws file updated, same ws path, same inode (os.stat(ws).st_ino), marker intact
def test_resync_keeps_placeholders_and_redacts_new_secret(project, fake): # add fake.github() to repo -> raw value not in ws; existing placeholder names unchanged
def test_resync_refuses_with_pending_changes(project): # edit ws -> ok False, ws file still edited
def test_resync_discard_throws_away_changes(project): # edit ws, discard=True -> ws matches original sanitized
def test_resync_allowed_after_full_integration(project): # edit ws, integrate(APPROVE) -> resync(discard=False) ok
def test_resync_after_partial_integration_requires_discard(project): # integrate(exclude_paths=("app/x",)) -> resync(discard=False) not ok
def test_resync_verification_failure_leaves_workspace_untouched(project, monkeypatch):
    # monkeypatch ai_safe.resync.verify_workspace to return a failing report
    # -> tree_snapshot(ws) unchanged, the session.json hash unchanged, no "<id>.resync" dir or extra ai-safe-ws-* dir left
def test_resync_refuses_inside_agent(project, monkeypatch): # setenv CLAUDECODE=1 -> SecurityError
def test_cli_resync_discard_requires_typed_word(project): # CliRunner input="no\n" -> exit 1, ws edit kept
def test_resync_output_has_no_secrets(project): # CLI output contains neither project.key nor project.pw
```

- [ ] **Step 2: Run them and confirm they fail.** Run `.venv/bin/pytest tests/test_resync.py -q`.
- [ ] **Step 3: Implement** `replace_tree_contents` in `workspace.py`. Use `secure_remove_tree` for child directories and `os.unlink` for files and symlinks.
- [ ] **Step 4: Implement** `resync.py`.
- [ ] **Step 5: Add the `resync` CLI command** in `cli.py`, wrapped with `@guarded`.
- [ ] **Step 6: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 7: Commit.** `git commit -m "feat: ai-safe resync rebuilds the workspace in place after staging verification"`

---

### Task 6: `ai-safe open`

**Files:**
- Create: `src/ai_safe/launcher.py`
- Modify: `src/ai_safe/cli.py`
- Test: `tests/test_launcher.py`

**Interfaces:**
- Consumes: `SecurityConfig.allow_ai_launch`, `launch_command`, `launch_env_allowlist`, `docker_image` (Task 1); `SessionStore.resolve`; `detect_ai_agent_env`.
- Produces:
  - `@dataclass LaunchOption(key: str, label: str, argv: list[str] | None, example: str)`.
  - `launch_options(ws: Path, cfg: AISafeConfig) -> list[LaunchOption]`, with the keys `"agent"`, `"vscode"`, `"docker"`, `"print"`.
  - `launch_env(cfg) -> dict[str, str]`: the allowlisted variables plus `AI_SAFE_AGENT=1`.
  - `run_option(opt: LaunchOption, ws: Path, env: dict[str, str]) -> int`. It returns the exit code, or 127 if the executable is not found.
  - `is_interactive() -> bool`, which checks `sys.stdin.isatty() and sys.stdout.isatty()`. Tests monkeypatch it.

Option details:

| Key | `argv` | `example` |
|---|---|---|
| agent | `cfg.security.launch_command`, run with `cwd=ws` | `cd <ws> && <launch_command joined>` |
| vscode | `["code", "-n", str(ws)]` | `code -n <ws>` |
| docker | `["docker", "run", "--rm", "-it", "-v", f"{ws}:/workspace", "-w", "/workspace", "-e", "AI_SAFE_AGENT=1", *(["-e", n] for allowlisted ANTHROPIC_* vars that are set), image, "claude"]` when `docker_image` is set and `shutil.which("docker")` exists; otherwise `None` | the same command with `<image-with-claude-code>` in place of the image |
| print | `None` | all the examples above |

CLI `ai-safe open [--session/-s] [--config/-c]`:
1. If `detect_ai_agent_env()`, raise `SecurityError("ai-safe open must be run by the developer, not by an AI agent")`.
2. Resolve the session. Refuse with exit 1 if `session.verified_tree_hash` is empty or the workspace is missing.
3. Print the workspace path and the reminder "verify/review run on the host".
4. If `not cfg.security.allow_ai_launch`, print the examples and the hint `security.allow_ai_launch: true`, then exit 0.
5. If `not is_interactive()`, print the examples and exit 2.
6. Otherwise show the menu with `typer.prompt` (choices 1–4).
   - For docker, when `argv is None` or `run_option` returns non-zero, print the docker example and the hint "set security.docker_image".
   - For agent or vscode, a non-zero code (127) prints the example.
   - "print" prints all the examples.

- [ ] **Step 1: Write the failing tests.**

```python
def test_open_refuses_inside_agent(project, monkeypatch): # CLAUDECODE=1 -> exit 3, the message contains "developer"
def test_open_prints_only_when_launch_disallowed(project, monkeypatch): # subprocess.run patched to fail if called -> exit 0, "code -n" in output
def test_open_non_tty_prints_and_exits_2(project_allow_launch, monkeypatch): # is_interactive -> False
def test_open_vscode_choice_runs_code(project_allow_launch, monkeypatch): # input "2\n" -> recorded argv == ["code","-n",ws]
def test_open_agent_env_is_allowlisted(project_allow_launch, monkeypatch): # setenv SOME_TOKEN=x; choice 1 -> env has AI_SAFE_AGENT=1, no SOME_TOKEN, cwd == ws
def test_open_docker_without_image_prints_example(project_allow_launch, monkeypatch): # choice 3 -> subprocess not called, "<image-with-claude-code>" in output
def test_open_docker_failure_prints_example(project_allow_launch, monkeypatch): # docker_image set, which->"/usr/bin/docker", run rc=125 -> example printed
def test_open_refuses_unverified_session(project, monkeypatch): # session.verified_tree_hash=None; save -> exit 1
```

`project_allow_launch` is the `project` fixture with `cfg.security.allow_ai_launch = True` written to `repo/ai-safe.yaml` before `prepare`, so the CLI loads it.

- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement** `launcher.py`.
- [ ] **Step 4: Add the CLI command.** Use `@app.command("open")` and name the function `open_cmd` so it does not shadow the builtin `open`. Also change the `start` output so the "Launch" section prints `ai-safe open` as the first option.
- [ ] **Step 5: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 6: Commit.** `git commit -m "feat: ai-safe open launches an AI agent, VSCode or Docker on the verified workspace"`

---

### Task 7: Docs and skills

**Files:**
- Modify: `README.md`, `AGENTS.md`, `SECURITY.md`, `docs/HOW_IT_WORKS_BM.md`
- Modify: `src/ai_safe/skill_templates/ai-safe/SKILL.md`, `src/ai_safe/skill_templates/ai-safe-review/SKILL.md`, then copy both to `skills/`
- Test: `tests/test_security.py::test_main_skill_covers_required_rules`

- [ ] **Step 1: Write the failing test.** Extend the phrase tuple in `test_main_skill_covers_required_rules` with `"ai-safe open"`, `"do not install ai-safe"` and `"run on the host"`.
- [ ] **Step 2: Run it and confirm it fails.** Run `.venv/bin/pytest tests/test_security.py -q -k skill`.
- [ ] **Step 3: Update the `ai-safe` skill.**
  - The "not a workspace" stop message (around line 30) now says: run `ai-safe start` and then `ai-safe open` in your own terminal.
  - Add a section, "When `ai-safe` is not available": if `command -v ai-safe` fails, or `ai-safe verify` reports no session (Docker, local install), do not install ai-safe and do not search for it. Finish the work and ask the developer to run `ai-safe verify` and `ai-safe review` on the host, inside the workspace path.
  - Add one line saying team skills, commands and agents edited here will be shown to the developer for review before integration.
  - Add the same fallback paragraph to `ai-safe-review`.
  - Copy both files to `skills/`.
- [ ] **Step 4: Update README.**
  - Add a "Quick Start: ask your AI to install" section with the prompt: "Install ai-safe for me (ask me global or local). If this project is not a Git repository, initialise Git first. Add `.ai-safe/` and `.claude/settings.local*.json` to .gitignore. Ask me before changing scan_ignored." This is followed by: "Then run `ai-safe start` and `ai-safe open` yourself in a normal terminal."
  - Add `open`, `resync` and `docker_image` to the command and config reference.
  - Update the `.claude/` paragraph (line 333) to describe the team-path policy.
- [ ] **Step 5: Update AGENTS.md.**
  - §2 gets a "Pre-installation: ensure Git repository" step (`git rev-parse --git-dir 2>/dev/null || git init`, after asking the user).
  - §2 gets a step to ask before setting `scan_ignored`, without reading ignored files.
  - Add `resync` and `open` to the "Never run" list in §3.
  - Reword the §4 AI-launch rule to: "no automatic launch; `ai-safe open` launches only on a human's menu choice with `allow_ai_launch: true`".
  - Add a new "## 5. Opening a session in the workspace" that explains that the user runs `ai-safe open` or `cd <ws> && claude` / `code -n <ws>` themselves, and covers `resync`.
- [ ] **Step 6: Update SECURITY.md.** Add rows for:
  - resync staging (verification before any byte reaches the live workspace)
  - team `.claude` redaction and settings merge (dangerous keys dropped)
  - the `agent-instructions` warning and the `ai-safe-install` block
  - `open` refusing in agent sessions and its env allowlist
  - the config combination rejection

  Each row names its test. Add a short note on the same flows to `docs/HOW_IT_WORKS_BM.md`.
- [ ] **Step 7: Run the full suite.** Run `.venv/bin/pytest -q`. Expected: all pass, including `test_skills_complete_and_in_sync`.
- [ ] **Step 8: Commit.** `git commit -m "docs: open/resync, team .claude policy, install quick start; skill fallbacks"`
