# MF-05 AMC State Analysis

## Scope

This sprint adds deterministic AMC-facing state analysis over one supplied
`MemoryEvent`.

Added:

- `MemoryStateAssertion`;
- `AuthorityAssessment`;
- `StateContradiction`;
- `AMCMapping`;
- `StateAnalysisResult`;
- `analyze_memory_state(event, existing_assertions=...)`;
- `memory-firewall analyze --event <path|-> --json`;
- `memory-firewall schema state-assertion`;
- `memory-firewall schema state-analysis`;
- README and product-contract updates.

## Intent

MF-05 connects detector output to the `agent-memory-contracts` trust-kernel
shape without pretending to run a reducer or write trusted memory. The output is
an explainable candidate/evidence preview plus local contradiction handling.

The acceptance test is:

```text
A low-authority contradiction cannot silently become trusted state.
```

In this sprint, that means a low-authority event conflicting with an existing
assertion emits `blocked_low_authority_contradiction`, carries explicit reason
codes, and leaves the AMC candidate preview in `needs_review`.

## Non-Goals

- No automatic approval by an LLM.
- No scan/watch ingestion.
- No quarantine queue or override workflow.
- No trusted-read broker.
- No real framework adapter.
- No hosted service.
- No `MemoryGate.promote` call.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No release/tag/publish.
- No new `agent-memory-contracts` schema, ID, or v2 semantics.

## Claim Budget

Allowed:

- Memory Firewall can derive a deterministic local state assertion from a
  supplied `MemoryEvent`.
- Memory Firewall can assess declared source authority.
- Memory Firewall can compare a candidate assertion against caller-supplied
  existing assertions and emit deterministic contradictions.
- Memory Firewall can produce AMC `SourceRecord`, `EvidenceSpan`, and
  `CandidateClaim` preview records that validate against
  `agent-memory-contracts==1.3.0`.
- Sensitive candidate text is redacted from the AMC preview when MF-04
  detector output indicates secret-like or privacy-sensitive content.
- Low-authority contradictions are blocked from trusted-state handling.

Not allowed:

- Memory Firewall proves which assertion is true.
- Memory Firewall promotes memory to trusted state.
- Memory Firewall scans a live store for existing assertions.
- Memory Firewall quarantines, enforces, or suppresses framework memory.
- Memory Firewall automatically accepts high-authority updates; they are only
  supersession candidates for later reducer review.

## Review Focus

- Does MF-05 avoid reintroducing the MF-04 secret-output leak through AMC
  candidate text, source records, evidence spans, CLI output, or schemas?
- Are generated AMC source/span/candidate records actually validated by
  `agent-memory-contracts==1.3.0`?
- Is the low-authority contradiction rule deterministic and test-covered?
- Are supersession candidates only suggestions, not trusted-state writes?
- Does `can_skip_reducer_review` stay false?
- Are schema and runtime validation aligned?
- Do README and product contract avoid scanner, quarantine, trusted-read,
  adapter, enforcement, and automatic-approval claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema state-assertion
uv run --python 3.12 --extra dev memory-firewall schema state-analysis
uv run --python 3.12 --extra dev memory-firewall analyze --event event.json --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf05-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf05-dist/*
```

## Local Gate Results

Base before draft PR creation:

- `origin/main`: `0960f3e4fcd549bc777c74f5ed9d1212e1138619`

Passed locally:

- focused MF-05/schema/CLI tests:
  `uv run pytest tests/test_analysis.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `34` passed
- full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - `101` passed
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310 uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311 uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 22 source files`
- bytecode smoke:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema state-assertion`
  - `memory-firewall schema state-analysis`
  - `memory-firewall claims --json`
  - `memory-firewall analyze --event <fixture> --json`
  - JSON validation passed and a secret-like fixture was absent from serialized
    analysis output
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-full uv build --out-dir /tmp/memory-firewall-mf05-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf05-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev5-py3-none-any.whl` into
    `/tmp/memory-firewall-mf05-wheel-venv`
  - `uv pip check --python /tmp/memory-firewall-mf05-wheel-venv/bin/python`
  - installed console script smokes for `doctor`, `schema state-analysis`,
    `claims --json`, and `analyze --event <fixture> --json`
  - installed-wheel analysis output was checked for sample secret absence

## Initial Review Findings And Fix Pass

Independent reviewer `Gibbs`
(`019ee623-64fd-74d0-9bac-17ae75b3f6e9`) requested changes on exact head
`687b93646c872cfa2c3e2abbcdea42453a655c6a`.

Blocking findings:

- `metadata.state_object` could contain a secret-like value that detectors never
  saw, causing `analyze --json` to republish it through the assertion object,
  AMC `EvidenceSpan.text_excerpt`, and AMC `CandidateClaim` text.
- `event.actor` could contain a secret-like value and be republished through
  AMC `SourceRecord.author_or_sender` and `participants`.
- `MemoryStateAssertion.from_dict()` accepted schema-invalid existing assertion
  inputs: unknown fields and malformed `source_event_id` values.

Fix-pass changes:

- Added analysis-layer secret recognition/redaction for metadata-derived
  subject, predicate, object, actor, and namespace output.
- Redact the assertion object when detector findings require it, when the raw
  object itself matches a recognized secret-like value, or when subject/predicate
  carry secret-label hints such as `api_key`, `token`, or `password`.
- Drop secret-like actors from AMC `author_or_sender` and `participants` rather
  than echoing them.
- Reject unknown `MemoryStateAssertion` fields and require
  `source_event_id` to match the canonical `mfev_v1_[0-9a-f]{32}` shape.
- Added regression coverage for metadata-only secret leakage, opaque
  `api_key` predicate values, actor leakage, unknown assertion fields, and
  malformed event ids.

Fix-pass gates:

- focused MF-05/schema/CLI tests:
  `uv run pytest tests/test_analysis.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `38` passed
- full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - `105` passed
- type checks:
  - Python `3.10`, `3.11`, and `3.12` mypy all reported
    `Success: no issues found in 22 source files`
- bytecode smoke:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `doctor`, `schema bundle`, `schema state-assertion`,
    `schema state-analysis`, `claims`, and `analyze`
  - metadata-object and actor secret fixture was absent from analysis output
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-full uv build --out-dir /tmp/memory-firewall-mf05-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf05-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev5-py3-none-any.whl`
  - `uv pip check` passed
  - installed `analyze --event <fixture> --json` confirmed metadata-object and
    actor secrets were absent from output
