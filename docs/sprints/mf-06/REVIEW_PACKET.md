# MF-06 Scan And Watch

## Scope

This sprint adds bounded local execution over normalized `MemoryEvent` streams:

- `scan_jsonl_events(...)`;
- `iter_scan_records(...)`;
- `watch_stdin_events(...)`;
- `memory-firewall scan <events.jsonl>`;
- `memory-firewall watch --stdin`;
- `memory-firewall schema scan-result`;
- README and product-contract updates.

The implementation composes existing MF-04/MF-05 surfaces:

```text
MemoryEvent JSONL
  -> deterministic detectors
  -> deterministic policy recommendations
  -> deterministic state analysis
  -> scan/watch result
```

## Intent

MF-06 makes Memory Firewall runnable against local event streams without
pretending to be a live adapter or trusted ledger.

The acceptance test is:

```text
Scan/watch normalized memory-event streams deterministically, with explicit
PASS/WARN/HIGH-RISK output and no raw invalid-line echo.
```

## Non-Goals

- No hosted ingestion.
- No real framework adapter.
- No live memory-store scanner.
- No directory/file watcher beyond explicitly supplied JSONL input.
- No quarantine storage.
- No allow/reject UI.
- No trusted-read broker.
- No reference proxy or enforce mode.
- No `MemoryGate.promote` call.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No release/tag/publish.
- No automatic LLM approval.

## Claim Budget

Allowed:

- Memory Firewall can scan a finite JSONL file of normalized `MemoryEvent`
  records.
- Memory Firewall can watch normalized `MemoryEvent` JSONL from stdin.
- Scan/watch output composes deterministic detectors, policy, and state
  analysis.
- Scan-local assertion context can surface contradictions across a JSONL
  stream when prior events are clean and review-eligible.
- Scan-local context is fixed-cap and does not retain low-authority/high-risk
  candidates as future state.
- Invalid JSONL lines are reported as structured issues without echoing raw
  input line content.
- Exit codes distinguish clean completion, high-risk findings, and invalid
  input.

Not allowed:

- Memory Firewall scans a live memory store.
- Memory Firewall watches a real agent framework.
- Memory Firewall quarantines, suppresses, approves, or promotes memory.
- Scan-local assertion context is trusted state.
- `HIGH-RISK` proves objective falsity, adversarial intent, or universal memory
  poisoning.

## Review Focus

- Does scan/watch preserve the MF-05 rule that low-authority contradictions
  cannot silently become trusted state?
- Does invalid-line handling avoid echoing raw line content, raw secrets, or
  raw secret digests?
- Does scan-local assertion context stay local and bounded rather than becoming
  an implicit ledger?
- Can low-authority/high-risk candidates influence later contradiction state?
- Are exit codes deterministic and documented?
- Are JSON schema and runtime output aligned?
- Does watch mode handle `KeyboardInterrupt` without a traceback?
- Do README and product contract avoid real-store scanning, adapter, quarantine,
  trusted-read, and enforce claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_scan.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema scan-result
uv run --python 3.12 --extra dev memory-firewall scan events.jsonl --json
uv run --python 3.12 --extra dev memory-firewall scan events.jsonl --json --summary-only
uv run --python 3.12 --extra dev memory-firewall watch --stdin --json < events.jsonl
git diff --check
uv build --out-dir /tmp/memory-firewall-mf06-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf06-dist/*
```

## Local Gate Results

Base before draft PR creation:

- `origin/main`: `f20a9f1de2e63ffca55384b59fd5819bc03b8d82`

Initial focused gates:

- focused MF-06/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_scan.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `35` passed
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/scan.py src/memory_firewall/cli.py tests/test_scan.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 5 source files`

Full gates passed:

- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - `116` passed before fix-pass; `117` passed after the exact-head review
    fix-pass
- type checks:
  - `uv run --python 3.10 --extra dev mypy src tests`
  - `uv run --python 3.11 --extra dev mypy src tests`
  - `uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 24 source files`
- bytecode smoke:
  `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema scan-result`
- scan/watch smoke:
  - generated a canonical two-line `MemoryEvent` JSONL stream;
  - `memory-firewall scan <events.jsonl> --json --summary-only` returned exit
    code `1`, reported one high-risk event, and omitted per-event records;
  - `memory-firewall watch --stdin --json < events.jsonl` returned exit code
    `1` and emitted one JSONL record per event.
- fix-pass regressions after exact-head review:
  - two contradictory untrusted JSONL events do not produce
    `blocked_low_authority_contradiction`;
  - watch interruption returns exit code `130`;
  - watch records flush per line.
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `uv build --out-dir /tmp/memory-firewall-mf06-dist`
  - `uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf06-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev6-py3-none-any.whl` into
    `/tmp/memory-firewall-mf06-wheel-venv`;
  - installed console script smokes for `doctor`, `schema scan-result`, `scan`,
    and `watch`;
  - scan/watch installed-wheel smoke verified the expected high-risk exit code
    and output shape;
  - `uv pip check` passed.

## Exact-Head Review Fix Pass

Independent reviewer `Rawls`
(`019ee669-7b11-7a31-bf33-338525b10bda`) reviewed exact head
`3ec19a025ece0433d91360c254b03c753e731364` and requested changes.

Blocking findings:

- watch-mode scan-local assertion context was unbounded, so long-running watch
  streams could grow with stream cardinality;
- every valid event, including low-authority or high-risk candidates, was fed
  back as future contradiction context, creating an implicit ledger-like
  influence;
- watch output was not flushed per record;
- interrupted watch runs could return clean exit code `0`.

Fix-pass changes:

- added fixed-cap scan context with `DEFAULT_SCAN_CONTEXT_ASSERTIONS = 1024`;
- only clean, review-eligible events can seed scan-local context;
- low-authority or high-risk candidates are not retained as future state;
- watch JSONL/text output flushes per record;
- interrupted watch returns `SCAN_EXIT_INTERRUPTED = 130`;
- product contract and README clarify that scan context is bounded,
  review-eligible, and not trusted state;
- added regression coverage for contradictory untrusted events and interrupted
  watch exit behavior.

Fix-pass gates:

- focused MF-06/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_scan.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `36` passed
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/scan.py src/memory_firewall/cli.py tests/test_scan.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 5 source files`
- full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - `117` passed
- type checks:
  - Python `3.10`, `3.11`, and `3.12` mypy all reported
    `Success: no issues found in 24 source files`
- bytecode smoke:
  `UV_PROJECT_ENVIRONMENT=.venv-312-compile uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `doctor`, `schema bundle`, and `schema scan-result`
- scan/watch smoke:
  - generated a canonical two-line `MemoryEvent` JSONL stream;
  - scan and watch returned the expected high-risk exit code `1`;
  - summary-only scan omitted per-event records;
  - watch emitted one JSONL result per event.
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf06-fix-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf06-fix-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev6-py3-none-any.whl` into
    `/tmp/memory-firewall-mf06-fix-wheel-venv`;
  - installed console script smokes for `doctor`, `schema scan-result`, `scan`,
    and `watch`;
  - scan/watch installed-wheel smoke verified the expected high-risk exit code
    and output shape;
  - `uv pip check` passed.
