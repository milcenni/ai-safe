"""`.claude/` path policy and scanner skips for ai-safe's own install and skills."""

import pytest

from ai_safe.classifier import ClaudePath, claude_path_policy, is_pristine_ai_safe_skill, sensitive_match
from ai_safe.config import AISafeConfig
from ai_safe.scanner import Scanner
from ai_safe.workspace import skill_template
from conftest import builtin_config

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
