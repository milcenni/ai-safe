# PHP Legacy Credential Dataflow (Stage 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In legacy PHP projects, find credential literals that reach a credential sink (`mysqli_connect`, `new PDO`, `ftp_login`, …) through variables, include files, constants, properties and wrapper functions. Redact them so that at least 90% (weighted) of planted credentials in a legacy-PHP benchmark never reach the workspace.

**Architecture:** This adds a repo-level pass that runs after the per-file detector in `Scanner.scan`. It traces every non-literal argument in a sink's user or password slot back to string literals and returns ordinary `Finding`s. The sanitizer, verifier and credential map then handle those findings unchanged. Phase B is regex-based and has no dependencies: variables, `include`, `global`, constants and properties. Phase C adds function and method parameter tracing with tree-sitter, as an optional extra. A benchmark built first measures recall and gates Phase C.

**Tech Stack:** Python 3.11+, pytest. Optional: `tree-sitter>=0.23`, `tree-sitter-php>=0.23` (PyPI wheels; Phase C only).

**Spec:** No separate spec document. The design was agreed in conversation on 2026-11-27 and is summarised in "Design decisions" below. The executor treats that section as the spec.

## Design decisions (the spec)

1. **Target:** legacy/custom PHP only. Frameworks are already covered by key-name rules (Stage 1).
2. **Success:** benchmark weighted recall ≥ 0.90, and the false-positive guard corpus produces zero findings.
3. **Sinks:** the `_SINKS` table in `src/ai_safe/php_calls.py` is the single source of truth, shared by Stage 1 and Stage 2.
4. **Over-approximate when unsure.** Several candidate assignments or functions mean all are reported. Wrongly redacting a value is acceptable; leaking it is not.
5. **Sources that are not credentials are never reported and never warned about:** `getenv`, `$_ENV`, `$_SERVER`, `$_POST`, `$_GET`, `$_REQUEST`, `$_COOKIE`, `config(...)`, `env(...)` without a literal default.
6. **Usernames** follow the Stage 1 rules: reported only together with a literal password, never when they are a common default or host-like.
7. **Unresolvable dynamic calls that carry literals (decision pending, default (a)):** report the literals conservatively when some sink-reaching function's password position fits the argument count. The user may switch this to warn-only; that is a one-line change in Task 6.
8. **Untraceable sink arguments** (expression, unresolved include, depth limit) produce a scan **warning** with file and line only, never a value. They never cause a failure or an exclusion.
9. **Config:** `scanner.php_dataflow: Literal["auto", "on", "off"] = "auto"`. `off` disables B and C. `auto` runs B, and C when tree-sitter is importable. `on` requires tree-sitter and fails closed like a missing Gitleaks.
10. **Scope of the pass:** working-tree files only. History, staged and unstaged chunks keep the per-file rules, because they are partial texts.

## Global Constraints

- Tests use synthetic values generated at runtime only. No literal credential-shaped strings in source, tests, fixtures, docs or skills (AGENTS.md §4).
- Never put a secret value into messages, warnings, logs or exceptions. Warnings carry rule, file and line only.
- Security changes update `SECURITY.md` (one threat row per task that changes detection) and the README "Security limitations". T27 is taken by email sanitization, so the T-numbers in this plan shift to the next free ones.
- `skills/` stays identical to `src/ai_safe/skill_templates/`.
- No new hard dependency. tree-sitter is an optional extra (`ai-safe[php]`).
- Trace depth limit: 8 hops. Include depth limit: 8. Both are cycle-safe.
- Full suite command: `.venv/bin/pytest -q`. It must be green at the end of every task.

## Review Focus

1. **Short or common values redacted everywhere.** Values of 8+ characters are replaced in every file, so a traced `$host = 'database01'` wrongly classified as a password corrupts code. Only user and password slots are traced, never host or db slots. Test: `test_host_and_dbname_slots_never_traced` (Task 3).
2. **Include cycles and self-includes** (`a.php` includes `b.php`, which includes `a.php`) must terminate. Test: `test_include_cycle_terminates` (Task 4).
3. **Huge or minified PHP files** must not make the scan quadratic. The pass must finish in under 5 s on 2,000 generated files. Test: `test_dataflow_scales_linearly` (Task 4).
4. **Secrets in warnings.** An untraceable-argument warning must never contain the variable's value. Test: `test_dataflow_warnings_contain_no_values` (Task 3).
5. **Reassignment** (`$pw = 'a'; … $pw = 'b';`) reports both literals, never only the last one. Test: `test_reassigned_variable_reports_all_literals` (Task 3).

---

## File Structure

| File | Responsibility |
|---|---|
| `tests/legacy_corpus.py` (create) | Benchmark pattern catalog: templates with `{PW}`/`{USER}` markers, weight, owning phase |
| `tests/test_legacy_benchmark.py` (create) | Fills templates with synthetic values, runs scan and sanitize, computes weighted recall, guards false positives |
| `src/ai_safe/classifier.py` (modify) | Compound password key names (`dbpass`, `smtppwd`, …) |
| `src/ai_safe/php_calls.py` (modify) | Expose sink slots (`iter_sink_slots`), classify `$var`, `CONST`, `$this->prop` arguments |
| `src/ai_safe/php_dataflow.py` (create) | Phase B: repo-level tracing (variables, include graph, `global`, constants, properties) |
| `src/ai_safe/php_ast.py` (create) | Phase C: tree-sitter adapter, function and call-site index, parameter tracing |
| `src/ai_safe/scanner.py` (modify) | Run the dataflow pass after the working-tree loop; append findings and warnings |
| `src/ai_safe/review.py` (modify) | Run the dataflow pass on changed PHP files (AI-introduced credentials) |
| `src/ai_safe/config.py` (modify) | `ScannerConfig.php_dataflow` |
| `src/ai_safe/detectors.py` (modify) | SQL-dump password rules |
| `pyproject.toml`, `install.sh`, `AGENTS.md` (modify) | `php` extra and `--php` installer flag |

---

### Task 0: Branch and commit Stage 1

**Files:** none new.

- [ ] **Step 1:** Ask the user for permission, then `git switch -c feat/php-call-credentials` from the current HEAD.
- [ ] **Step 2:** Run `.venv/bin/pytest -q`. Expected: all pass (348 at the time of writing).
- [ ] **Step 3:** Commit `src/ai_safe/php_calls.py`, `src/ai_safe/detectors.py`, `tests/test_php_calls.py`, `README.md`, `SECURITY.md` with message `feat: detect credentials passed positionally to PHP calls`.

---

### Task 1: Legacy benchmark (measure before building)

**Files:**
- Create: `tests/legacy_corpus.py`, `tests/test_legacy_benchmark.py`

**Interfaces:**
- Produces: `Pattern(name: str, files: dict[str, str], weight: int, phase: str)`, where `phase` is one of `"stage1"`, `"A"`, `"B"`, `"C"`, `"D"`; `PATTERNS: list[Pattern]`; `NOT_SECRETS: dict[str, str]`, a corpus that must produce zero findings. Templates use `{PW}` and `{USER}`, which are filled with `str.format`, so literal braces are written `{{ }}`.

Patterns. Weights are initial estimates that the user adjusts with real samples. Total weight 100.

| name | phase | weight | shape |
|---|---|---|---|
| `literal-in-sink` | stage1 | 15 | `mysql_connect('localhost', '{USER}', '{PW}')` |
| `define-constant` | stage1 | 10 | `define('DB_PASS', '{PW}')` |
| `config-array-index` | stage1 | 8 | `$config['db']['password'] = '{PW}'` |
| `named-var-config` | stage1 | 7 | `$db_password = '{PW}';` |
| `compound-var-name` | A | 8 | `$dbpass = '{PW}';` (no sink in the file) |
| `short-var-same-file` | B | 8 | `$pw = '{PW}'; mysqli_connect('db', '{USER}', $pw);` |
| `include-config-vars` | B | 12 | `config.php`: `$u='{USER}'; $p='{PW}';`; `db.php`: `require 'config.php'; mysqli_connect('db', $u, $p);` |
| `sibling-include` | B | 6 | `index.php` includes `config.php` then `db.php`; `db.php` uses `$p` without including config |
| `global-in-function` | B | 5 | `$p='{PW}'; function db(){ global $p; return mysqli_connect('db','app',$p); }` |
| `odd-constant-name` | B | 3 | `define('X1', '{PW}'); mysqli_connect('db','app',X1);` |
| `class-property` | B | 4 | `class Db { var $k = '{PW}'; function c(){ return new mysqli('db','app',$this->k); } }` |
| `wrapper-function` | C | 6 | `function open_db($u,$p){ return mysqli_connect('db',$u,$p); } open_db('{USER}','{PW}');` |
| `wrapper-cross-file` | C | 3 | wrapper in `lib.php`, call in `index.php` |
| `call-user-func` | C | 2 | `call_user_func('open_db', '{USER}', '{PW}')` |
| `sql-dump` | D | 3 | `dump.sql`: `CREATE USER 'app'@'%' IDENTIFIED BY '{PW}';` |

- [ ] **Step 1: Write `tests/legacy_corpus.py`** with the 15 patterns above and `NOT_SECRETS`. `NOT_SECRETS` must contain at least: `bypass`/`compass` identifiers, `$host = 'database01'; mysqli_connect($host, $u, getenv('P'))`, `$dbname = 'shop_prod'`, `$pw = $_POST['pw']`, `$pw = getenv('DB_PASS')`, `include $path;`, and `ldap_bind($ds)`.

- [ ] **Step 2: Write `tests/test_legacy_benchmark.py`**

```python
@pytest.mark.parametrize("pattern", PATTERNS, ids=lambda p: p.name)
def test_pattern_never_reaches_workspace(pattern, make_repo, request):
    if pattern.phase not in IMPLEMENTED_PHASES:
        request.applymarker(pytest.mark.xfail(strict=True, reason=f"phase {pattern.phase}"))
    pw, user = word(6) + "7", word(7)
    p = prepare(make_repo({k: v.format(PW=pw, USER=user) for k, v in pattern.files.items()}))
    assert pw not in all_text(p.ws)

def test_weighted_recall_report(make_repo, capsys): ...   # prints recall; asserts >= RECALL_FLOOR

def test_not_secrets_produce_no_findings(make_repo):
    p = prepare(make_repo(NOT_SECRETS))
    assert p.scan.findings == []
```

`IMPLEMENTED_PHASES = {"stage1"}` and `RECALL_FLOOR = 0.40` (the stage1 weight sum ÷ 100) are module constants. Each later task adds its phase and raises the floor to the new weight sum. `word()` is the helper from `tests/test_php_calls.py`; move it to `conftest.py` as `short_word(rng, n)`.

- [ ] **Step 3:** Run `.venv/bin/pytest -q tests/test_legacy_benchmark.py`. Expected: stage1 patterns PASS, every other pattern XFAIL, recall test PASS, NOT_SECRETS PASS. If a stage1 pattern fails, fix the template (it is meant to document existing behaviour) and do not change any detector.
- [ ] **Step 4:** Commit: `test: legacy PHP credential benchmark`.

---

### Task 2 (Phase A): Compound password key names

**Files:**
- Modify: `src/ai_safe/classifier.py` (`is_sensitive_key`, `is_password_key`)
- Test: `tests/test_key_names.py` (create)

**Interfaces:**
- Produces: `split_compound_password(word: str) -> bool` in `classifier.py`. It is True when a lowercased word is `<prefix><suffix>`, with prefix in `{"db","mysql","sql","pg","mssql","oracle","mongo","admin","root","smtp","ftp","sftp","mail","imap","pop","ldap","redis","amqp","rabbit","user","app","api","ssh","svc","service","master","sa","web","site","login"}` and suffix in `{"pass","passwd","password","pwd","pw"}`.

- [ ] **Step 1: Write failing tests**

```python
@pytest.mark.parametrize("key", ["dbpass", "DBPASS", "dbpwd", "mysqlpassword", "smtppass", "ftppw", "adminpasswd"])
def test_compound_password_keys_are_password_keys(key):
    assert is_sensitive_key(key) and is_password_key(key)

@pytest.mark.parametrize("key", ["bypass", "compass", "surpass", "passthrough", "trespass", "dbpath", "apipassthrough"])
def test_ordinary_words_are_not_password_keys(key):
    assert not is_password_key(key)

def test_compound_var_detected_in_php():
    v = "Zq" + short_word(random.Random(1), 6)
    assert [m.secret for m in BuiltinDetector().scan_text(f"<?php\n$dbpass = '{v}';\n", "c.php")] == [v]
```

- [ ] **Step 2:** Run `.venv/bin/pytest -q tests/test_key_names.py`. Expected: FAIL on the compound cases.
- [ ] **Step 3:** Implement `split_compound_password` and use it in both predicates (a word matches if it is in the existing password set or `split_compound_password(word)`).
- [ ] **Step 4:** Add `"A"` to `IMPLEMENTED_PHASES` and raise `RECALL_FLOOR` to 0.48. Run the full suite. Expected: PASS.
- [ ] **Step 5:** Update the README limitations (compound names) and add `SECURITY.md` row T27 "Credential in a variable with a compound name". Commit: `feat: recognise compound password key names (dbpass, smtppwd, ...)`.

---

### Task 3 (Phase B, part 1): Same-file variable, constant and property tracing

**Files:**
- Modify: `src/ai_safe/php_calls.py`
- Create: `src/ai_safe/php_dataflow.py`
- Modify: `src/ai_safe/scanner.py` (`Scanner.scan`, after the working-tree loop)
- Modify: `src/ai_safe/config.py` (`ScannerConfig.php_dataflow`)
- Test: `tests/test_php_dataflow.py` (create)

**Interfaces:**
- Produces in `php_calls.py`:
  - `Arg.kind` gains `"var"` (`value` = name without `$`), `"const"` (bare identifier, `value` = name), `"prop"` (`$this->x`, `self::$x`, `static::$x`; `value` = `x`), and `"source"` (a non-credential source from decision 5).
  - `SinkSlot(role: str, arg: Arg, sink: Sink, file: str, line: int)`
  - `iter_sink_slots(text: str, path: str) -> Iterator[SinkSlot]`. It yields every user/password slot of every known sink and of `*connect` wrappers, whatever the argument kind. `find_call_credentials` is reimplemented on top of it (literal slots only), and Stage 1 tests must stay green.
- Produces in `php_dataflow.py`:
  - `FlowFinding(file: str, start: int, end: int, line: int, secret: str, role: str, category: Category, key: str, rule_id: str = "php-dataflow")`
  - `FlowWarning(file: str, line: int, reason: str)`, where reason is one of `"expression"`, `"unresolved-include"`, `"depth-limit"`, `"unresolved-dynamic-call"`
  - `trace_php(texts: dict[str, str]) -> tuple[list[FlowFinding], list[FlowWarning]]`, where `texts` holds rel path → text for PHP files only
- Consumes: `Sink`, `_usable`, `_user_ok` from `php_calls.py`.

- [ ] **Step 1: Write failing tests** in `tests/test_php_dataflow.py`. Values come from a seeded `random.Random`.

```python
def test_same_file_short_variable():            # $pw = '{p}'; mysqli_connect('db', 'app', $pw);  -> [p]
def test_reassigned_variable_reports_all_literals():  # $pw='{a}'; ... $pw='{b}'; connect(.., $pw) -> {a, b}
def test_constant_any_name():                   # define('X1','{p}') / const X1 = '{p}'; connect(.., X1) -> [p]
def test_class_property():                      # var $k = '{p}'; ... new mysqli('db','app',$this->k) -> [p]
def test_user_reported_only_with_password():    # $u='{u}'; $p=getenv('P'); connect('db',$u,$p) -> []
def test_non_credential_sources_ignored():      # $p = $_POST['p'] / getenv(...) / config('x') -> [] and no warnings
def test_host_and_dbname_slots_never_traced():  # $host='{h}'; $db='{d}'; mysqli_connect($host,'app','{p}',$db) -> only p
def test_expression_argument_warns():           # connect('db','app',$a . $b) -> [], warnings == [FlowWarning(file, line, "expression")]
def test_dataflow_warnings_contain_no_values(): # str(warning) and scan --json output never contain any planted value
def test_php_dataflow_off_disables_pass():      # cfg.scanner.php_dataflow = "off" -> pattern short-var-same-file reaches workspace
```

Each test asserts on `trace_php({"a.php": text})` results (`{f.secret for f in findings}`), except the last two, which go through `Scanner`/`prepare`.

- [ ] **Step 2:** Run `.venv/bin/pytest -q tests/test_php_dataflow.py`. Expected: ImportError/FAIL.
- [ ] **Step 3:** Extend `parse_args` classification and add `iter_sink_slots`. Rebuild `find_call_credentials` on it. Run `.venv/bin/pytest -q tests/test_php_calls.py`. Expected: PASS (no Stage 1 regression).
- [ ] **Step 4:** Implement `trace_php` for a single file. Build a per-file index of `$name = <string literal>;` assignments (all occurrences), `define('NAME', '<lit>')` / `const NAME = '<lit>'` (repo-wide index, because constants are global), and property declarations `(var|public|protected|private|static)\s+\$name\s*=\s*'<lit>'`. Resolve each slot through the index; apply `_usable`/`_user_ok`; report usernames only if the same call's password slot resolved to at least one literal. Literal offsets point into the assignment's file.
- [ ] **Step 5:** Add `php_dataflow: Literal["auto", "on", "off"] = "auto"` to `ScannerConfig`. In `Scanner.scan`, after the working-tree loop and unless the setting is `off`, call `trace_php({rel: t for rel, t in texts.items() if is_php(rel)})`. Convert each `FlowFinding` with `self._finding(..., engine="builtin", location=files[f.file])`, and append each `FlowWarning` to `result.warnings` as `f"php-dataflow: {w.reason} at {w.file}:{w.line}"`.
- [ ] **Step 6:** Run the full suite. Expected: PASS. Benchmark: `short-var-same-file`, `odd-constant-name` and `class-property` are now XPASS(strict), which fails the run. Add `"B"` to `IMPLEMENTED_PHASES` only after Task 4. Until then, mark these three patterns `phase="B1"`, add `"B1"`, and raise `RECALL_FLOOR` to 0.63.
- [ ] **Step 7:** Add a `SECURITY.md` row T28 "Credential reaches a PHP sink through a variable, constant or property", plus a README limitation update. Commit: `feat: trace PHP sink arguments to same-file variables, constants and properties`.

---

### Task 4 (Phase B, part 2): Include graph and `global`

**Files:**
- Modify: `src/ai_safe/php_dataflow.py`
- Test: `tests/test_php_dataflow.py`

**Interfaces:**
- Produces: `include_graph(texts: dict[str, str]) -> tuple[dict[str, set[str]], set[str]]`. It returns the edges (file → included files) and the set of files that contain an unresolvable include.
- Resolution rules: `(include|require)(_once)?` with argument `'lit'`, `__DIR__ . '/lit'`, `dirname(__FILE__) . '/lit'`, or `"lit"` without `$`. The path is resolved against the including file's directory, then against the repo root, normalised, and must exist in `texts`. Anything else counts as unresolvable.
- Scope for a slot in file S: the union of assignment indexes of all files in the **undirected connected component** of S in the include graph (this covers sibling includes). If that component contains an unresolvable include and the slot is still unresolved, fall back to a repo-wide lookup of that variable name, following decision 4, and emit `FlowWarning(S, line, "unresolved-include")`.
- `global $x;` inside a function body makes `$x` resolve through the component scope. Without `global`, function-local lookups still use the component scope (over-approximation, decision 4).

- [ ] **Step 1: Write failing tests**

```python
def test_variables_from_required_config():       # include-config-vars pattern -> {u, p}
def test_sibling_include_via_entry_file():       # sibling-include pattern -> {p}
def test_dir_and_dirname_include_forms():        # __DIR__ . '/inc/config.php' and dirname(__FILE__) . '/../config.php'
def test_global_in_function():                   # global-in-function pattern -> {p}
def test_include_cycle_terminates():             # a.php <-> b.php, both include each other; returns, finds p
def test_unresolvable_include_falls_back_and_warns():  # include $path; -> finds p repo-wide, one "unresolved-include" warning
def test_unrelated_file_not_in_scope():          # other.php (no include link) has $p='{q}' -> q not reported
def test_dataflow_scales_linearly():             # 2,000 generated files, 50 includes each chain -> trace_php < 5 s
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `include_graph` and component scoping in `trace_php`. Use iterative BFS, never recursion. Cap component traversal at depth 8 from S, and emit `"depth-limit"` when the cap is hit.
- [ ] **Step 4:** Rename the `B1` patterns back to `B`, add `"B"` to `IMPLEMENTED_PHASES`, and raise `RECALL_FLOOR` to 0.86. Run the full suite. Expected: PASS.
- [ ] **Step 5: Review integration.** In `review.py`, run `trace_php` over the workspace's PHP texts (changed and unchanged), so that context like config files is included. Keep only findings whose literal lies on an AI-added line of a changed file, and report them via the existing `hardcoded-credential` ERROR. Test: `test_review_blocks_ai_introduced_traced_credential` (AI adds `$pw = '{p}';` and `mysqli_connect('db','app',$pw)` in the workspace; the review is not passed).
- [ ] **Step 6:** Update `SECURITY.md` T28 (include graph, `global`, review). Commit: `feat: trace PHP credentials through include graphs and globals`.

**Gate:** Run `.venv/bin/pytest -q tests/test_legacy_benchmark.py -s` and report the printed weighted recall to the user. If recall is ≥ 0.90 on their adjusted weights, Task 5 is optional and the user decides.

---

### Task 5 (Phase C): Function and method parameter tracing (tree-sitter)

**Files:**
- Create: `src/ai_safe/php_ast.py`
- Modify: `src/ai_safe/php_dataflow.py`, `src/ai_safe/scanner.py`, `pyproject.toml`, `install.sh`, `AGENTS.md`, `README.md`
- Test: `tests/test_php_ast.py` (create; whole module `pytest.importorskip("tree_sitter_php")`)

**Interfaces:**
- Produces in `php_ast.py`:
  - `available() -> bool`
  - `require() -> None`. It raises `SecurityError("scanner.php_dataflow=on requires the optional 'php' extra (tree-sitter); install ai-safe[php] or set scanner.php_dataflow: auto")`.
  - `FunctionDef(key: str, file: str, params: list[str], defaults: dict[int, tuple[int, int, str]], body_span: tuple[int, int])`, where `key` is the lowercased `name`, or `class::method` for methods, or `closure@file:offset`
  - `CallSite(callee_keys: set[str], file: str, args: list[Arg], enclosing: str | None, dynamic: bool)`. `call_user_func('f', …)` gives `{"f"}` with arguments shifted by one; `[$o, 'm']` / `'C::m'` / `$o->m()` give every key ending in `::m`; `$f = 'name'; $f(…)` resolves through the local assignment; an unresolvable name gives `dynamic=True` and an empty set.
  - `index_php(texts: dict[str, str]) -> tuple[dict[str, FunctionDef], list[CallSite]]`
- Produces in `php_dataflow.py`: `trace_php(texts, *, ast: bool = False)`. With `ast=True`, a slot whose argument is a parameter of its enclosing `FunctionDef` is traced to every `CallSite` whose `callee_keys` contains that function. At each call site, the corresponding argument is resolved with the Task 3/4 resolver: literal, var, const or prop, or another parameter (pushed onto the worklist). Literal defaults of that parameter are reported too. The worklist key is `(function_key, param_index, role)`, with a visited set and a depth limit of 8.
- Dynamic calls follow decision 7, option (a): for each `dynamic=True` call site whose arg count ≥ the password position of any sink-reaching function, report its string literals at those positions.
- Scanner: `auto` passes `ast=php_ast.available()`; `on` calls `php_ast.require()` in `Scanner.__init__`; `off` skips the pass.

- [ ] **Step 1: Write failing tests**

```python
def test_wrapper_function_same_file():        # wrapper-function pattern -> {u, p}
def test_wrapper_cross_file():                # wrapper-cross-file -> {u, p}
def test_two_level_wrapper():                 # custom_connect -> custom_connectv2 -> new PDO (user's original example) -> {u, p}
def test_call_user_func_literal_name():       # call-user-func pattern -> {u, p}
def test_method_and_constructor():            # class Db { function __construct($u,$p){ $this->c = new PDO('x',$u,$p); } } new Db('{u}','{p}')
def test_parameter_default_literal():         # function f($p = '{p}') { return mysqli_connect('db','app',$p); }
def test_function_names_case_insensitive():   # define open_db, call OPEN_DB('{u}','{p}')
def test_recursion_terminates():              # f($p){ return $x ? f($p) : mysqli_connect('db','app',$p); } f('{p}')
def test_dynamic_call_conservative():         # $fn = $_GET['f']; $fn('{u}', '{p}') with a sink-reaching 2-param function present -> {u, p}
def test_php_dataflow_on_without_tree_sitter_fails_closed(monkeypatch):  # monkeypatch php_ast.available -> False; Scanner(...) raises SecurityError
```

- [ ] **Step 2:** `.venv/bin/pip install tree-sitter tree-sitter-php`, then run `.venv/bin/pytest -q tests/test_php_ast.py`. Expected: FAIL.
- [ ] **Step 3:** Implement `php_ast.py`. Load the grammar with `tree_sitter.Language(tree_sitter_php.language_php())`. Map the node types `function_definition`, `method_declaration`, `anonymous_function`, `arrow_function`, `function_call_expression`, `member_call_expression`, `scoped_call_expression`, `object_creation_expression` (callee `class::__construct`). Convert arguments to the existing `Arg` kinds, so the resolver is shared.
- [ ] **Step 4:** Implement the worklist in `trace_php(ast=True)` and wire it into the scanner and config behaviour.
- [ ] **Step 5:** Add `[project.optional-dependencies] php = ["tree-sitter>=0.23", "tree-sitter-php>=0.23"]`. In `install.sh`, add a `--php` flag that installs `"$SRC_DIR[php]"` and is described in `--help`. Update AGENTS.md §2 step 3 (consent covers the extra) and step 4 (flag). Add `"C"` to `IMPLEMENTED_PHASES` and raise `RECALL_FLOOR` to 0.97 only in a test environment where tree-sitter is installed; otherwise skip the C patterns with `importorskip`.
- [ ] **Step 6:** Run the full suite with and without tree-sitter installed (`pip uninstall -y tree-sitter-php tree-sitter` for the second run). Expected: PASS both times.
- [ ] **Step 7:** Add a `SECURITY.md` row T29 "Credential reaches a PHP sink through wrapper functions or dynamic calls" and update the README limitations. Commit: `feat: trace PHP credentials through function parameters (optional tree-sitter)`.

---

### Task 6 (Phase D): SQL dump passwords

**Files:**
- Modify: `src/ai_safe/detectors.py` (`TOKEN_RULES`, `_CONTEXT_TOKEN_RULES`)
- Test: `tests/test_php_dataflow.py`, or a new `tests/test_sql_dump.py`

**Interfaces:**
- Produces: token rules `sql-identified-by` (`IDENTIFIED (WITH \w+ )?BY '<secret>'`, case-insensitive), `sql-password-func` (`PASSWORD\('<secret>'\)`) and `sql-set-password` (`SET PASSWORD (FOR \S+ )?= '<secret>'`), all in category `DATABASE_CREDENTIAL` and members of `_CONTEXT_TOKEN_RULES`.

- [ ] **Step 1: Write failing tests:** the `sql-dump` pattern, `GRANT ALL ON *.* TO 'u'@'%' IDENTIFIED BY '{p}'`, `ALTER USER 'u' IDENTIFIED WITH mysql_native_password BY '{p}'`, and `SET PASSWORD FOR 'u'@'%' = '{p}'`. Each finds `p`. Negative case: `IDENTIFIED BY PASSWORD '*<41 hex>'` (an already-hashed value) and `-- IDENTIFIED BY '<placeholder>'` find nothing.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Add the three rules.
- [ ] **Step 4:** Add `"D"` to `IMPLEMENTED_PHASES` and raise `RECALL_FLOOR` by 0.03. Run the full suite. Expected: PASS.
- [ ] **Step 5:** Add a `SECURITY.md` row T30 and update the README. Commit: `feat: detect passwords in SQL dumps`.

---

## Out of scope (recorded so nobody adds them silently)

- Tracing in Git history, staged or unstaged chunks (partial texts). The per-file rules still apply there.
- `vendor/` code, framework DI containers, `eval`, `__call`/`__get` magic.
- String concatenation of credential fragments (warning only, from Task 3).
- Languages other than PHP. `php_ast` is designed so that a Python adapter could reuse `Arg`, `SinkSlot` and the resolver later.
