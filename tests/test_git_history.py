import subprocess

from ai_safe import git_history as gh
from ai_safe.models import Location
from ai_safe.scanner import Scanner
from conftest import all_text, builtin_config, git, prepare, write


def test_parse_added_chunks():
    diff = (
        "\x00commit abc123\n"
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n+++ b/x.py\n"
        "@@ -1,0 +5,2 @@\n+line5\n+line6\n"
        "@@ -9 +12 @@\n-old\n+new12\n"
        "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\n"
    )
    chunks = list(gh.parse_added_chunks(diff))
    assert [(c.path, c.start_line, c.lines, c.commit) for c in chunks] == [
        ("x.py", 5, ["line5", "line6"], "abc123"),
        ("x.py", 12, ["new12"], "abc123"),
    ]


def test_history_includes_deleted_files_and_all_refs(make_repo, fake):
    tok = fake.github()
    repo = make_repo({"keep.py": "x=1\n", "secret.py": f'T = "{tok}"\n'})
    git(repo, "rm", "-q", "secret.py")
    git(repo, "commit", "-q", "-m", "delete")
    texts = [c.text for c in gh.history_added_chunks(repo)]
    assert any(tok in t for t in texts)
    stats = gh.history_stats(repo)
    assert stats.commits == 2 and stats.branches == 1


def test_scan_does_not_execute_repo_controlled_git_drivers(make_repo, tmp_path, fake):
    """A malicious textconv / external diff driver configured in the repo must
    never run while ai-safe scans history or diffs."""
    pwned = tmp_path / "pwned"
    repo = make_repo({"a.py": f'API_KEY = "{fake.openai()}"\n', ".gitattributes": "*.py diff=evil\n"})
    git(repo, "config", "diff.evil.textconv", f"sh -c 'touch {pwned}; cat \"$0\"'")
    git(repo, "config", "diff.external", f"sh -c 'touch {pwned}'")
    write(repo, {"a.py": f'API_KEY = "{fake.openai()}"\nX = 2\n'})
    git(repo, "add", "a.py")
    write(repo, {"a.py": f'API_KEY = "{fake.openai()}"\nX = 3\n'})
    hooks = repo / ".git" / "hooks"
    (hooks / "post-checkout").write_text(f"#!/bin/sh\ntouch {pwned}\n")
    (hooks / "post-checkout").chmod(0o755)
    r = Scanner(builtin_config(), b"k" * 32).scan(repo)
    assert {Location.STAGED, Location.UNSTAGED, Location.HISTORY} <= {f.location for f in r.findings}
    assert not pwned.exists()


def test_scan_never_modifies_git_state(make_repo, fake):
    repo = make_repo({"a.py": f'K = "{fake.openai()}"\n'})
    before = subprocess.run(["git", "for-each-ref"], cwd=repo, capture_output=True).stdout
    idx_before = (repo / ".git" / "index").read_bytes()
    prepare(repo)
    assert subprocess.run(["git", "for-each-ref"], cwd=repo, capture_output=True).stdout == before
    assert (repo / ".git" / "index").read_bytes() == idx_before


def test_sanitized_history_summary_has_no_secrets_or_authors(make_repo, fake):
    tok = fake.github()
    repo = make_repo({"a.py": f'T = "{tok}"\n'})
    git(repo, "rm", "-q", "a.py")
    git(repo, "commit", "-q", "-m", f"remove token {tok}")
    cfg = builtin_config()
    cfg.sanitization.history_summary = True
    p = prepare(repo, cfg)
    text = (p.ws / "AI_SAFE_HISTORY.md").read_text()
    assert "Commits (all refs): 2" in text
    assert tok not in text and "t@example.invalid" not in text
    assert tok not in all_text(p.ws)


def test_ai_cannot_reach_original_history_from_workspace(make_repo, fake):
    repo = make_repo({"a.py": "x=1\n"})
    p = prepare(repo)
    # no git repository in the workspace: git commands fail (or resolve to an unrelated parent)
    res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=p.ws, capture_output=True, text=True)
    assert res.returncode != 0 or res.stdout.strip() != str(repo)
    # workspace never mentions the original repo path (marker, settings, skills)
    assert str(repo) not in all_text(p.ws)
    marker = (p.ws / ".ai-safe-workspace.json").read_text()
    assert "repo" not in marker.lower().replace("ai-safe", "")
