"""Regression tests for the issues found by the independent adversarial
security review (see docs/TEST_REPORT.md). All credentials are synthetic."""

import os
import random
import string
import threading

import pytest

from ai_safe.detectors import BuiltinDetector
from ai_safe.integration import integrate
from ai_safe.review import review_session
from ai_safe.security import safe_display, walk_nofollow
from conftest import all_text, prepare, write

APPROVE = lambda rr, patch: True  # noqa: E731


def rnd(n, alphabet=string.ascii_letters + string.digits, seed=[0]):
    seed[0] += 1
    r = random.Random(seed[0])
    return "".join(r.choice(alphabet) for _ in range(n))


def codes(rr):
    return {i.code for i in rr.issues if i.severity.blocking}


# 1. directory-swap race -------------------------------------------------------

def test_walk_never_reads_through_swapped_directory(tmp_path):
    root = tmp_path / "ws"
    (root / "x").mkdir(parents=True)
    (root / "x" / "f.txt").write_text("inside\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("OUTSIDE-CONTENT\n")
    stop = threading.Event()

    def swapper():
        while not stop.is_set():
            try:
                os.rename(root / "x", root / "x_real")
                os.symlink(outside, root / "x")
                os.unlink(root / "x")
                os.rename(root / "x_real", root / "x")
            except OSError:
                pass

    t = threading.Thread(target=swapper)
    t.start()
    try:
        for _ in range(300):
            for e in walk_nofollow(root):
                assert not (e.data and b"OUTSIDE" in e.data)
    finally:
        stop.set()
        t.join()


# 2. secret leaking into placeholder names / mapping ------------------------

def test_url_username_token_not_used_as_placeholder_name(make_repo):
    tok = "ghp_" + rnd(36)
    hexkey = rnd(40, "0123456789abcdef")
    repo = make_repo({
        "ci.sh": f'git clone "https://{tok}:x-oauth-basic@github.com/org/repo.git"\n',
        "deploy.py": f'URL = "https://{hexkey}:x@api.example.com/v1"\n',
    })
    p = prepare(repo)
    text = all_text(p.ws)
    st = all_text(p.session.state_path.parent.parent / "sessions" / p.session.id)
    for v in (tok, hexkey):
        norm = "".join(c for c in v.upper() if c.isalnum())
        assert v not in text and norm not in "".join(c for c in text.upper() if c.isalnum())
        assert v not in (p.session.state_path / "credential-map.json").read_text()
        assert norm not in "".join(c for c in st.upper() if c.isalnum())
    assert p.verification.passed


# 3. detector gaps --------------------------------------------------------------

GAP_CASES = {
    "settings.py": lambda v: f'CACHE_URL = "redis://:{v}@cache:6379/0"\n',
    "app.ini": lambda v: f"[db]\npassword = Xy7#{v}\n",
    "app.properties": lambda v: f"db.password=Ab9;{v}\n",
    "deploy.sh": lambda v: f"#!/bin/sh\nmysql -u root -p{v} mydb < dump.sql\n",
    "deploy2.sh": lambda v: f"sshpass -p '{v}' ssh host\n",
    "deploy3.sh": lambda v: f"curl -u admin:{v} https://api.internal.example/x\n",
    "client.py": lambda v: f'headers = {{"Authorization": "Basic {v}=="}}\n',
    "jdbc.py": lambda v: f'URL = "jdbc:postgresql://db:5432/app?user=app&password={v}"\n',
    "db.py": lambda v: f'DB_PASSWORD = "Zz$({v}"\n',
    "conn.cs": lambda v: f'var cs = "Server=db;Database=app;User Id=sa;Password={v};";\n',
    "Dockerfile": lambda v: f"ENV DB_PASSWORD {v}\n",
    "tf.tf": lambda v: f"password = <<EOF\n{v}\nEOF\n",
    "auth.py": lambda v: f'auth = HTTPBasicAuth("svc", "{v}")\n',
    "Props.java": lambda v: f'props.put("password", "{v}");\n',
    "Str.java": lambda v: f'String password = new String("{v}");\n',
    "b.go": lambda v: f'var pw = []byte("{v}")\n',
    "tuple.py": lambda v: f'creds = ("admin", "{v}")\n',
    "envdefault.py": lambda v: f'client = Client(api_key=os.environ.get("K", "sk{v}{v}"))\n',
    "commented.py": lambda v: f"# old password was Cp{v}\n",
    "multi.env.example": lambda v: f"API_TOKEN={v}{v}\n",
    "docker-cfg.json": lambda v: f'{{"auths": {{"registry.example.com": {{"auth": "{v}{v}"}}}}}}\n',
}


@pytest.mark.parametrize("name", sorted(GAP_CASES))
def test_detector_gap_forms_are_detected(name):
    value = "Q" + rnd(15)
    text = GAP_CASES[name](value)
    found = BuiltinDetector().scan_text(text, name)
    assert any(value in m.secret for m in found), (name, [m.rule_id for m in found])


def test_detector_gap_forms_never_reach_workspace(make_repo):
    values, files = [], {}
    for name, fn in GAP_CASES.items():
        v = "Q" + rnd(15)
        values.append(v)
        files[name] = fn(v)
    p = prepare(make_repo(files))
    text = all_text(p.ws)
    assert [v for v in values if v in text] == []
    assert p.verification.passed


# 4. new files under ignored / tool directories ----------------------------

def test_new_file_in_ignored_directory_rejected(make_repo):
    repo = make_repo({".gitignore": ".venv/\nbuild/\n", "app.py": "x=1\n"})
    (repo / ".venv" / "lib").mkdir(parents=True)
    p = prepare(repo)
    write(p.ws, {".venv/lib/site-packages/zz_ai.pth": "import os\n", "build/out.txt": "x\n"})
    rr = review_session(p.session, p.cfg, p.scanner)
    assert {i.path for i in rr.issues if i.code == "ignored-path"} == {".venv/lib/site-packages/zz_ai.pth", "build/out.txt"}
    assert not rr.plan


# 5. .gitignore weakening ------------------------------------------------------

def test_gitignore_weakening_blocked(make_repo):
    repo = make_repo({".gitignore": ".env\n*.log\n", "app.py": "x=1\n"})
    p = prepare(repo)
    (p.ws / ".gitignore").write_text("*.log\n")
    assert "ignore-weakened" in codes(review_session(p.session, p.cfg, p.scanner))
    (p.ws / ".gitignore").write_text(".env\n*.log\n!.env.local\n")
    assert "ignore-weakened" in codes(review_session(p.session, p.cfg, p.scanner))
    (p.ws / ".gitignore").write_text(".env\n*.log\n*.tmp\n")
    rr = review_session(p.session, p.cfg, p.scanner)
    assert rr.passed and any(i.code == "sensitive-config" for i in rr.issues)


# 6. terminal control characters -----------------------------------------------

def test_ansi_and_bidi_blocked_and_escaped(make_repo):
    p = prepare(make_repo({"util.py": "x=1\n"}))
    (p.ws / "util.py").write_text("x=1\n__import__('os').system('id')\x1b[2K\x1b[1G# harmless\n")
    assert "hidden-characters" in codes(review_session(p.session, p.cfg, p.scanner))
    (p.ws / "util.py").write_text("x=1\naccess = 'user‮ ⁦// admin⁩ ⁦'\n")
    assert "hidden-characters" in codes(review_session(p.session, p.cfg, p.scanner))
    shown = safe_display("a\x1b[2Kb‮c\x9bd")
    assert "\x1b" not in shown and "‮" not in shown and "\x9b" not in shown and "<U+001B>" in shown


# 7. deletion of a file the developer changed ---------------------------------

def test_deletion_of_changed_original_refused(make_repo):
    repo = make_repo({"notes.txt": "v1\n", "app.py": "x=1\n"})
    p = prepare(repo)
    (repo / "notes.txt").write_text("v2 - developer edit\n")
    (p.ws / "notes.txt").unlink()
    res = integrate(p.session, p.cfg, p.scanner, confirm=APPROVE, cwd=repo)
    assert res.aborted and (repo / "notes.txt").read_text() == "v2 - developer edit\n"
    assert any(i.code == "original-changed" for i in res.review.issues)


def test_detector_false_positive_guard(make_repo):
    """New rules must not flag common non-secret code."""
    text = (
        'import os\npassword = os.environ["DB_PASSWORD"]\nmkdir -p build\n'
        'url = "https://example.com:8443/path"\nc = Config(password=None)\n'
        "# reset your password in settings\nheaders['Authorization'] = 'Basic ' + encoded\n"
        'pw = getpass.getpass()\nDB_URL = "postgres://${DB_USER}:${DB_PASS}@db/app"\n'
        "password: ${DB_PASSWORD}\n"
    )
    assert BuiltinDetector().scan_text(text, "x.py") == []
    assert BuiltinDetector().scan_text("password: ${DB_PASSWORD}\nsecret: {{ vault_secret }}\n", "c.yaml") == []
