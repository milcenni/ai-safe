"""Weighted recall of credential sanitization on the legacy-PHP benchmark
(tests/legacy_corpus.py). Patterns whose phase is not implemented yet are
strict xfails, so finishing a phase forces this file to be updated."""

import random

import pytest

from conftest import all_text, prepare, short_word
from legacy_corpus import NOT_SECRETS, PATTERNS, Pattern

from ai_safe import php_ast  # noqa: E402

# Phase C (function tracing) needs the optional tree-sitter extra.
IMPLEMENTED_PHASES = {"stage1", "A", "B1", "B"} | ({"C"} if php_ast.available() else set())
RECALL_FLOOR = 0.97 if php_ast.available() else 0.86

_R = random.Random(2026)


def _leaks(pattern: Pattern, make_repo) -> bool:
    pw, user = short_word(_R, 6) + "7", short_word(_R, 7)
    p = prepare(make_repo({k: v.format(PW=pw, USER=user) for k, v in pattern.files.items()}, name=f"r-{pattern.name}"))
    return pw in all_text(p.ws)


@pytest.mark.parametrize("pattern", PATTERNS, ids=lambda p: p.name)
def test_pattern_never_reaches_workspace(pattern, make_repo, request):
    if pattern.phase == "C" and not php_ast.available():
        pytest.skip("phase C needs the optional 'php' extra (tree-sitter)")
    if pattern.phase not in IMPLEMENTED_PHASES:
        request.applymarker(pytest.mark.xfail(strict=True, reason=f"phase {pattern.phase}"))
    assert not _leaks(pattern, make_repo)


def test_weighted_recall_report(make_repo, capsys):
    caught = sum(p.weight for p in PATTERNS if not _leaks(p, make_repo))
    recall = caught / sum(p.weight for p in PATTERNS)
    with capsys.disabled():
        print(f"\nlegacy-PHP weighted recall: {recall:.2f}")
    assert recall >= RECALL_FLOOR


def test_not_secrets_produce_no_findings(make_repo):
    p = prepare(make_repo(NOT_SECRETS))
    assert [(f.file, f.rule_id) for f in p.scan.findings] == []
