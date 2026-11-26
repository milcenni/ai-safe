"""`.claude/` path policy and scanner skips for ai-safe's own install and skills."""

import json
from pathlib import Path

import pytest

from ai_safe.classifier import ClaudePath, claude_path_policy, is_pristine_ai_safe_skill, sensitive_match
from ai_safe.config import AISafeConfig
from ai_safe.scanner import Scanner
from ai_safe.workspace import claude_settings, merge_claude_settings, skill_template
from conftest import builtin_config, prepare

SALT = b"s" * 32


@pytest.mark.parametrize("rel,expected", [
    (".ai-safe/bin/ai-safe", ClaudePath.INSTALL), (".claude/ai-safe/x", ClaudePath.INSTALL),
    (".claude/skills/ai-safe/SKILL.md", ClaudePath.AI_SAFE_SKILL),
    (".claude/skills/ai-safe-review/extra.md", ClaudePath.AI_SAFE_SKILL),
    (".claude/skills/deploy/SKILL.md", ClaudePath.TEAM), (".claude/commands/x.md", ClaudePath.TEAM),
    (".claude/agents/r.md", ClaudePath.TEAM), (".claude/settings.json", ClaudePath.SETTINGS),
    (".claude/settings.local.json", ClaudePath.OTHER), (".claude/hooks/h.sh", ClaudePath.OTHER),
    ("app/x.py", ClaudePath.NONE),
])
def test_claude_path_policy(rel, expected):
    assert claude_path_policy(rel) == expected


@pytest.mark.parametrize("rel,expected", [
    (".AI-SAFE/bin/x", ClaudePath.INSTALL), (".Claude/AI-Safe/x", ClaudePath.INSTALL),
    (".CLAUDE/Skills/AI-SAFE/SKILL.md", ClaudePath.AI_SAFE_SKILL),
    (".Claude/Commands/x.md", ClaudePath.TEAM), (".claude/Settings.JSON", ClaudePath.SETTINGS),
    (".claude", ClaudePath.NONE), ("src/.claude/settings.json", ClaudePath.NONE),
])
def test_claude_path_policy_is_case_insensitive(rel, expected):
    assert claude_path_policy(rel) == expected


def test_sensitive_match_carves_out_team_only():
    ex = AISafeConfig().sanitization.all_excludes()
    assert sensitive_match(".claude/skills/deploy/SKILL.md", ex) is None
    assert sensitive_match(".claude/skills/deploy/.env", ex) is not None
    assert sensitive_match(".claude/settings.local.json", ex) == ".claude/"
    assert sensitive_match(".claude/settings.json", ex) is None
    assert sensitive_match(".claude/skills/ai-safe/SKILL.md", ex) is not None
    assert sensitive_match(".claude/ai-safe/x", ex) is not None


def test_is_pristine_ai_safe_skill(tmp_path):
    rel = ".claude/skills/ai-safe/SKILL.md"
    p = tmp_path / rel
    p.parent.mkdir(parents=True)
    p.write_bytes(skill_template("ai-safe").encode("utf-8"))
    assert is_pristine_ai_safe_skill(tmp_path, rel)
    p.write_bytes(skill_template("ai-safe").encode("utf-8") + b"\n")
    assert not is_pristine_ai_safe_skill(tmp_path, rel)
    (p.parent / "extra.md").write_text("x\n")
    assert not is_pristine_ai_safe_skill(tmp_path, ".claude/skills/ai-safe/extra.md")
    assert not is_pristine_ai_safe_skill(tmp_path, ".claude/skills/deploy/SKILL.md")
    assert not is_pristine_ai_safe_skill(tmp_path, ".claude/skills/ai-safe-scan/SKILL.md")  # missing


def test_scanner_skips_install_dirs_and_pristine_skills(make_repo, fake):
    repo = make_repo({
        ".ai-safe/lib.py": f'TOKEN = "{fake.github()}"\n',
        ".claude/ai-safe/x.txt": f'TOKEN = "{fake.github()}"\n',
        ".claude/skills/ai-safe/SKILL.md": skill_template("ai-safe"),
        ".claude/skills/ai-safe-scan/SKILL.md": skill_template("ai-safe-scan") + f'\nTOKEN = "{fake.github()}"\n',
    })
    r = Scanner(builtin_config(scanner__scan_git_history=False), SALT).scan(repo)
    assert {f.file for f in r.findings} == {".claude/skills/ai-safe-scan/SKILL.md"}


def _entry(p, rel):
    return next(e for e in p.result.entries if e.path == rel)


def _ws_settings(p):
    return json.loads((p.ws / ".claude" / "settings.json").read_text())


def _gen_settings(p):
    return claude_settings(Path(p.session.state_dir).parent.parent)


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


def test_merge_settings_full_rules_and_no_mutation():
    gen = claude_settings(Path("/tmp/state"))
    gen_before = json.loads(json.dumps(gen))
    first_deny = gen["permissions"]["deny"][0]
    team = {k: "x" for k in ("hooks", "env", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport",
                             "otelHeadersHelper", "statusLine", "enabledMcpjsonServers")}
    team["_comment"] = "team comment"
    team["permissions"] = {"deny": ["Read(./a)", first_deny, "Read(./a)"], "ask": [first_deny, "Bash(ls)"],
                           "allow": [first_deny], "additionalDirectories": ["/"]}
    team_before = json.loads(json.dumps(team))
    m = merge_claude_settings(team, gen)
    assert set(m) == {"_comment", "permissions"}
    assert m["_comment"] == gen["_comment"]
    deny = m["permissions"]["deny"]
    assert deny == ["Read(./a)", first_deny] + [d for d in gen["permissions"]["deny"] if d != first_deny]
    assert m["permissions"]["ask"] == ["Bash(ls)"] and m["permissions"]["allow"] == []
    assert team == team_before and gen == gen_before
    m["permissions"]["deny"].append("mutated")
    assert gen == gen_before and team == team_before


@pytest.mark.parametrize("team", [None, [], "x", 3])
def test_merge_settings_non_dict_returns_generated(team):
    gen = claude_settings(Path("/tmp/state"))
    assert merge_claude_settings(team, gen) == gen


def test_merge_settings_malformed_permissions():
    gen = claude_settings(Path("/tmp/state"))
    m = merge_claude_settings({"permissions": ["bad"]}, gen)
    assert m["permissions"]["deny"] == gen["permissions"]["deny"]
    m = merge_claude_settings({"permissions": {"deny": "bad", "allow": "Bash(git push:*)"}}, gen)
    assert m["permissions"]["deny"] == gen["permissions"]["deny"]
    assert "allow" not in m["permissions"]


def test_team_claude_files_copied_and_settings_merged(make_repo):
    team = {
        ".claude/skills/deploy/SKILL.md": "# deploy skill\n",
        ".claude/commands/t.md": "run tests\n",
        ".claude/agents/a.md": "agent\n",
    }
    repo = make_repo({
        **team,
        ".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash(npm test)"]}, "hooks": {}}),
        ".claude/settings.local.json": "{}",
        ".claude/hooks/h.sh": "echo",
    })
    p = prepare(repo)
    for rel, text in team.items():
        assert (p.ws / rel).read_text() == text, rel
    assert p.verification.passed, p.verification.issues
    assert not (p.ws / ".claude" / "settings.local.json").exists()
    assert not (p.ws / ".claude" / "hooks" / "h.sh").exists()
    s = _ws_settings(p)
    assert "Bash(npm test)" in s["permissions"]["allow"]
    assert "hooks" not in s
    assert set(_gen_settings(p)["permissions"]["deny"]) <= set(s["permissions"]["deny"])
    assert _entry(p, ".claude/settings.json").action == "merged"


def test_team_skill_secret_redacted(make_repo, fake):
    secret = fake.openai()
    repo = make_repo({".claude/commands/deploy.md": f'API_KEY = "{secret}"\n'})
    p = prepare(repo)
    text = (p.ws / ".claude" / "commands" / "deploy.md").read_text()
    assert secret not in text
    assert "${AI_SAFE_SECRET_" in text
    assert p.verification.passed, p.verification.issues


def test_team_settings_secret_redacted_before_merge(make_repo, fake):
    secret = fake.openai()
    repo = make_repo({".claude/settings.json": json.dumps({"model": "opus", "note": f'API_KEY = "{secret}"'})})
    p = prepare(repo)
    raw = (p.ws / ".claude" / "settings.json").read_text()
    assert secret not in raw
    assert _ws_settings(p)["model"] == "opus"
    assert p.verification.passed, p.verification.issues


def test_invalid_team_settings_json_excluded(make_repo):
    repo = make_repo({".claude/settings.json": "{not json"})
    p = prepare(repo)
    assert _ws_settings(p) == _gen_settings(p)
    e = _entry(p, ".claude/settings.json")
    assert e.action == "excluded" and "invalid JSON" in e.reason


def test_team_settings_symlink_not_merged(make_repo, tmp_path):
    (tmp_path / "outside.json").write_text(json.dumps({"permissions": {"allow": ["Bash(rm:*)"]}}))
    repo = make_repo({"README.md": "x\n"})
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").symlink_to(tmp_path / "outside.json")
    p = prepare(repo)
    assert _ws_settings(p) == _gen_settings(p)
    assert _entry(p, ".claude/settings.json").action == "excluded"


def test_team_settings_not_leaked_between_runs(make_repo):
    from ai_safe.sanitizer import Sanitizer
    from ai_safe.scanner import Scanner as _Scanner
    from ai_safe.workspace import SessionStore, state_root

    cfg = builtin_config()
    a = make_repo({".claude/settings.json": json.dumps({"model": "opus"})}, name="a")
    b = make_repo({"README.md": "x\n"}, name="b")
    store = SessionStore(state_root(cfg))
    scanner = _Scanner(cfg, SALT)
    san = Sanitizer(cfg, scanner, SALT)
    for repo in (a, b):
        scan = scanner.scan(repo)
        session = store.create(scan.root, cfg)
        san.run(scan, session)
    s = json.loads((session.workspace_path / ".claude" / "settings.json").read_text())
    assert "model" not in s
