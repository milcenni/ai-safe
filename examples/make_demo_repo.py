#!/usr/bin/env python3
"""Create a demo Git repository with SYNTHETIC credentials for trying ai-safe.

    python examples/make_demo_repo.py /tmp/ai-safe-demo

The template in examples/sample-project contains only markers; this script fills
them with randomly generated, credential-shaped fake values and builds a short
history that includes a secret removed from HEAD but still present in history.
No real credential is ever used.
"""

from __future__ import annotations

import random
import shutil
import string
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "sample-project"


def fake_values(seed: int = 1337) -> dict[str, str]:
    r = random.Random(seed)
    alnum = string.ascii_letters + string.digits

    def rnd(n: int, alphabet: str = alnum) -> str:
        return "".join(r.choice(alphabet) for _ in range(n))

    body = "\n".join(rnd(64, alnum + "+/") for _ in range(6))
    return {
        "__FAKE_OPENAI_KEY__": "sk-proj-" + rnd(40),
        "__FAKE_DB_PASSWORD__": "Pw-" + rnd(14),
        "__FAKE_YAML_PASSWORD__": "Yp-" + rnd(14),
        "__FAKE_AWS_KEY_ID__": "AKIA" + rnd(16, string.ascii_uppercase + string.digits),
        "__FAKE_AWS_SECRET__": rnd(40, alnum + "+/"),
        "__FAKE_STRIPE_KEY__": "sk_live_" + rnd(24),
        "__FAKE_PRIVATE_KEY__": f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----",
        "__FAKE_OLD_TOKEN__": "ghp_" + rnd(36),
    }


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=demo", "-c", "user.email=demo@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=repo, check=True, stdout=subprocess.DEVNULL)


def main(dest: str) -> None:
    target = Path(dest).resolve()
    if target.exists() and any(target.iterdir()):
        sys.exit(f"{target} exists and is not empty")
    shutil.copytree(TEMPLATE, target, dirs_exist_ok=True)
    values = fake_values()
    for p in target.rglob("*"):
        if p.is_file():
            text = p.read_text()
            for k, v in values.items():
                text = text.replace(k, v)
            p.write_text(text)
    git(target, "init", "-q")
    # commit 1: a token that is later removed (remains in history)
    (target / "app" / "legacy.py").write_text(f'GITHUB_TOKEN = "{values["__FAKE_OLD_TOKEN__"]}"\n')
    git(target, "add", "-A")
    git(target, "commit", "-q", "-m", "Initial import")
    # commit 2: remove the legacy token file
    (target / "app" / "legacy.py").unlink()
    git(target, "add", "-A")
    git(target, "commit", "-q", "-m", "Remove legacy integration")
    git(target, "tag", "v0.1.0")
    print(f"demo repository created at {target}")
    print("all credentials are synthetic; try:  cd", target, "&& ai-safe start")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
