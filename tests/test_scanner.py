import json

import pytest
from typer.testing import CliRunner

from ai_safe.cli import app
from ai_safe.config import AISafeConfig, CustomRule, ScannerConfig
from ai_safe.detectors import BuiltinDetector
from ai_safe.models import Category, Location
from ai_safe.scanner import Scanner
from conftest import builtin_config, git, write

SALT = b"s" * 32


def scan(repo, cfg=None):
    return Scanner(cfg or builtin_config(), SALT).scan(repo)


def locs(result, file):
    return {f.location for f in result.findings if f.file == file}


def test_api_key_in_python_source(make_repo, fake):
    key = fake.openai()
    repo = make_repo({"app.py": f'OPENAI_API_KEY = "{key}"\n'})
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    [f] = [f for f in r.findings if f.location == Location.TRACKED]
    assert f.category == Category.API_KEY and f.file == "app.py" and f.line == 1
    assert f.secret == key and key not in repr(f) and "secret" not in f.public()


def test_database_password_in_env_is_found_as_ignored(make_repo, fake):
    pw = fake.password()
    repo = make_repo({".gitignore": ".env\n", "README.md": "x\n"})
    write(repo, {".env": f"DB_PASSWORD={pw}\n"})
    r = scan(repo)
    [f] = [f for f in r.findings if f.file == ".env"]
    assert f.location == Location.IGNORED
    assert f.category == Category.DATABASE_CREDENTIAL


def test_aws_credentials(make_repo, fake):
    kid, sec = fake.aws_key_id(), fake.aws_secret()
    repo = make_repo({"deploy.ini": f"[default]\naws_access_key_id = {kid}\naws_secret_access_key = {sec}\n"})
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    cats = {f.secret: f.category for f in r.findings}
    assert cats[kid] == Category.CLOUD_CREDENTIAL
    assert cats[sec] == Category.CLOUD_CREDENTIAL


def test_ssh_private_key_detected(make_repo, fake):
    repo = make_repo({"keys/deploy_key": fake.private_key("OPENSSH PRIVATE KEY") + "\n"})
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    assert any(f.category == Category.SSH_KEY for f in r.findings)


def test_password_in_yaml_and_json(make_repo, fake):
    p1, p2 = fake.password(), fake.password()
    repo = make_repo({
        "config.yaml": f"db:\n  host: x\n  password: {p1}\n",
        "creds.json": json.dumps({"client_secret": p2 + "Zq9"}),
    })
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    found = {f.file for f in r.findings}
    assert {"config.yaml", "creds.json"} <= found


def test_secret_in_untracked_file(make_repo, fake):
    repo = make_repo()
    write(repo, {"notes.py": f'token = "{fake.github()}"\n'})
    r = scan(repo)
    assert locs(r, "notes.py") == {Location.UNTRACKED}


def test_secret_in_staged_change(make_repo, fake):
    repo = make_repo({"a.py": "x = 1\n"})
    write(repo, {"a.py": f'x = 1\nSTRIPE_KEY = "{fake.stripe()}"\n'})
    git(repo, "add", "a.py")
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    staged = [f for f in r.findings if f.location == Location.STAGED]
    assert staged and staged[0].file == "a.py" and staged[0].line == 2


def test_secret_in_unstaged_change(make_repo, fake):
    repo = make_repo({"a.py": "x = 1\ny = 2\n"})
    write(repo, {"a.py": f'x = 1\ny = 2\nGITHUB_TOKEN = "{fake.github()}"\n'})
    r = scan(repo, builtin_config(scanner__scan_git_history=False))
    unstaged = [f for f in r.findings if f.location == Location.UNSTAGED]
    assert unstaged and unstaged[0].line == 3
    assert not [f for f in r.findings if f.location == Location.STAGED]


def test_secret_in_previous_commit_and_removed_from_head(make_repo, fake):
    tok = fake.github()
    repo = make_repo({"legacy.py": f'TOKEN = "{tok}"\n', "README.md": "x\n"})
    (repo / "legacy.py").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "remove legacy")
    r = scan(repo)
    hist = [f for f in r.findings if f.location == Location.HISTORY]
    assert hist and hist[0].file == "legacy.py" and hist[0].commit
    assert not [f for f in r.findings if f.location != Location.HISTORY]
    assert r.secrets_only_in_history  # rotation warning trigger


def test_history_covers_all_branches_and_tags(make_repo, fake):
    repo = make_repo()
    base = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, {"f.py": f'API_KEY = "{fake.openai()}"\n'})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "feature")
    git(repo, "tag", "v1")
    git(repo, "checkout", "-q", base)
    git(repo, "branch", "-D", "feature")  # reachable only from the tag now
    r = scan(repo)
    assert any(f.location == Location.HISTORY and f.file == "f.py" for f in r.findings)


def test_secret_in_commit_message(make_repo, fake):
    repo = make_repo()
    write(repo, {"b.txt": "b\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", f"oops token {fake.github()}")
    r = scan(repo)
    assert any(f.file == "<commit-message>" for f in r.findings)


def test_no_false_positives_for_env_lookups_and_placeholders(make_repo):
    repo = make_repo({
        "app.py": 'import os\npassword = os.environ["DB_PASSWORD"]\ntoken_type = "bearer"\n'
                  'API_KEY = "${AI_SAFE_SECRET_API_KEY}"\nmsg = "Enter your password"\npassword_field = "password"\n',
        "c.yaml": "password: ${DB_PASSWORD}\napi_key: <your-api-key>\n",
    })
    r = scan(repo)
    assert r.findings == []


def test_custom_rule():
    cfg = AISafeConfig(scanner=ScannerConfig(engine="builtin", custom_rules=[
        CustomRule(id="internal-token", regex=r"itk_(?P<secret>[a-f0-9]{24})", category=Category.ACCESS_TOKEN)
    ]))
    d = BuiltinDetector(cfg.scanner.custom_rules)
    [m] = [m for m in d.scan_text("x = itk_0123456789abcdef01234567\n", "a.txt") if m.engine == "custom"]
    assert m.category == Category.ACCESS_TOKEN and m.secret == "0123456789abcdef01234567"


def test_non_git_directory(tmp_path, fake):
    d = tmp_path / "plain"
    write(d, {"a.py": f'API_KEY = "{fake.openai()}"\n'})
    r = scan(d)
    assert r.findings and r.findings[0].location == Location.FILESYSTEM and not r.is_git


def test_cli_scan_never_prints_secret_and_report_is_clean(make_repo, fake, tmp_path):
    key, pw = fake.openai(), fake.password()
    repo = make_repo({"app.py": f'KEY = "{key}"\n', "c.yaml": f"password: {pw}\n"})
    cfgfile = tmp_path / "cfg.yaml"
    cfgfile.write_text("version: 1\nscanner:\n  engine: builtin\n")
    report = tmp_path / "report.json"
    res = CliRunner().invoke(app, ["scan", str(repo), "-c", str(cfgfile), "-o", str(report)])
    assert res.exit_code == 1, res.output
    assert key not in res.output and pw not in res.output
    text = report.read_text()
    assert key not in text and pw not in text
    data = json.loads(text)
    assert data["summary"]["total"] >= 2
    assert all("secret" not in f for f in data["findings"])


def test_cli_scan_clean_repo_exit_zero(make_repo, tmp_path):
    repo = make_repo({"a.py": "print('hi')\n"})
    cfgfile = tmp_path / "cfg.yaml"
    cfgfile.write_text("version: 1\nscanner:\n  engine: builtin\n")
    res = CliRunner().invoke(app, ["scan", str(repo), "-c", str(cfgfile)])
    assert res.exit_code == 0, res.output


def test_missing_gitleaks_fails_closed(make_repo, monkeypatch):
    repo = make_repo()
    monkeypatch.setattr("ai_safe.gitleaks.shutil.which", lambda name: None)
    monkeypatch.delenv("AI_SAFE_GITLEAKS", raising=False)
    res = CliRunner().invoke(app, ["scan", str(repo)])
    assert res.exit_code == 3
    assert "gitleaks is required" in res.output


@pytest.mark.gitleaks
def test_gitleaks_engine_all_locations(make_repo, fake, gitleaks_bin):
    old = fake.github()
    repo = make_repo({"legacy.py": f'TOKEN = "{old}"\n'})
    (repo / "legacy.py").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "rm")
    write(repo, {"new.py": f'TOKEN = "{fake.github()}"\n'})
    r = Scanner(AISafeConfig(), SALT).scan(repo)
    assert "gitleaks" in r.engines
    gl = [f for f in r.findings if "gitleaks" in f.engine]
    assert {f.location for f in gl} >= {Location.HISTORY, Location.UNTRACKED}


@pytest.mark.gitleaks
def test_import_gitleaks_json_report(make_repo, fake, gitleaks_bin, tmp_path):
    from ai_safe.gitleaks import Gitleaks

    other = tmp_path / "other"
    write(other, {"x.py": f'TOKEN = "{fake.github()}"\n'})
    recs = Gitleaks(gitleaks_bin).scan_dir(other)
    rep = tmp_path / "gl.json"
    rep.write_text(json.dumps(recs))
    repo = make_repo()
    r = Scanner(builtin_config(), SALT).scan(repo, gitleaks_report=rep)
    assert any(f.location == Location.IMPORTED for f in r.findings)
