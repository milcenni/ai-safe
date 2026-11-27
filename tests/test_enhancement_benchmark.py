"""Benchmark gate for the sanitizer gap analysis (tests/enhancement_corpus.py):

* **recall per category** - the fraction of tagged values that no longer
  appear anywhere in the workspace (secrets, usernames, identifiers, hosts);
* **corruption** - characters changed outside detected spans. Every
  placeholder in the sanitized text is replaced by the value it stands for
  (from the in-memory registry); the result must equal the original text.

Both are gated: recall must not drop below the floor, corruption must be 0."""

from __future__ import annotations

import difflib
import re

from conftest import all_text, prepare
from enhancement_corpus import render


RECALL_FLOOR = {"secret": 1.0, "username": 1.0, "identifier": 1.0, "host": 1.0}


def _prepared(make_repo):
    files, values = render()
    p = prepare(make_repo(files, name="bench"))
    return p, files, values


def _recall(text: str, values) -> dict[str, float]:
    low = text.lower()
    out = {}
    for cat in RECALL_FLOOR:
        vals = [v for c, v in values.values() if c == cat]
        out[cat] = sum(1 for v in vals if v.lower() not in low) / len(vals)
    return out


def _restore(text: str, registry) -> tuple[str, list[tuple[int, int, object]]]:
    """Restored text and the original span of every placeholder occurrence."""
    by_token = {e.token: e for e in registry.entries()}
    if not by_token:
        return text, []
    pattern = re.compile("|".join(re.escape(t) for t in sorted(by_token, key=len, reverse=True)))
    parts, spans, last, pos = [], [], 0, 0
    for m in pattern.finditer(text):
        e = by_token[m.group(0)]
        value = e.original or e.secret
        parts.append(text[last:m.start()])
        pos += m.start() - last
        spans.append((pos, pos + len(value), e))
        parts.append(value)
        pos += len(value)
        last = m.end()
    parts.append(text[last:])
    return "".join(parts), spans


def corruption(original: str, sanitized: str, registry) -> int:
    """Characters changed outside detected spans: lost characters (the restored
    text differs from the original; DNS names compare case-insensitively) plus
    replaced spans that cut a larger word (``prod_${...}``, ``${...}-server``)."""
    from ai_safe.redaction import DNS, dns_bounded, is_embedded

    restored, spans = _restore(sanitized, registry)
    lost = 0
    if restored.lower() != original.lower():
        sm = difflib.SequenceMatcher(None, original.lower(), restored.lower(), autojunk=False)
        lost = sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal")
        return lost
    cut = 0
    for s, e, entry in spans:
        whole = dns_bounded(original, s, e, entry.kind) if entry.propagate == DNS else not is_embedded(original, s, e)
        if not whole:
            cut += e - s
    return cut


def test_recall_per_category(make_repo, capsys):
    p, files, values = _prepared(make_repo)
    assert p.verification.passed, [i.public() for i in p.verification.issues if i.severity.blocking]
    recall = _recall(all_text(p.ws), values)
    with capsys.disabled():
        print("\nsanitizer gap benchmark recall: " + ", ".join(f"{k}={v:.2f}" for k, v in recall.items()))
    for cat, floor in RECALL_FLOOR.items():
        assert recall[cat] >= floor, (cat, [n for n, (c, v) in values.items() if c == cat and v.lower() in all_text(p.ws).lower()])


def test_values_that_must_be_kept(make_repo):
    p, files, values = _prepared(make_repo)
    text = all_text(p.ws)
    for name, (cat, v) in values.items():
        if cat == "keep":
            assert v in text, name


def test_zero_corruption(make_repo, capsys):
    p, files, values = _prepared(make_repo)
    total = 0
    per_file = {}
    for rel, original in files.items():
        out = (p.ws / rel)
        assert out.is_file(), f"{rel} was excluded"
        sanitized = out.read_text()
        n = corruption(original, sanitized, p.result.registry)
        per_file[rel] = n
        total += n
    with capsys.disabled():
        print(f"\nsanitizer gap benchmark corruption: {total} character(s)")
    assert total == 0, {k: v for k, v in per_file.items() if v}


def test_no_placeholder_glued_to_text(make_repo):
    from ai_safe.verify_checks import adjacency_issues, url_issues

    p, files, _ = _prepared(make_repo)
    for rel in files:
        text = (p.ws / rel).read_text()
        assert not adjacency_issues(text), (rel, adjacency_issues(text))
        assert not url_issues(text), rel


def test_corruption_metric_detects_over_replacement():
    from ai_safe.redaction import PlaceholderRegistry
    from ai_safe.models import Category

    reg = PlaceholderRegistry(b"k" * 32)
    e = reg.register("appsvc01", Category.USERNAME, "user")
    original = "user = 'appsvc01'\nlabel = 'prod_appsvc01'\n"
    good = original.replace("'appsvc01'", "'" + e.token + "'")
    bad = good.replace("prod_appsvc01", "prod_" + e.token)
    assert corruption(original, good, reg) == 0
    assert corruption(original, bad, reg) == len("appsvc01")
    assert corruption(original, good.replace("label", "lbl"), reg) > 0
