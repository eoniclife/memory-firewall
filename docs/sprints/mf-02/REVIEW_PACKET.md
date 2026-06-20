# MF-02 MemoryEvent And Adapter Capability Contract

## Scope

This sprint turns the MF-01 shell into an adapter-facing contract without adding
real memory integrations.

Added:

- deterministic `MemoryEvent` ids derived from canonical event material;
- stricter event/runtime validation and size bounds;
- adapter capability report model and schema;
- adapter conformance result model;
- built-in fake demo adapter for conformance smoke tests;
- `memory-firewall schema adapter`;
- `memory-firewall conformance demo --json`.

## Intent

MF-02 should let future adapters answer two questions before detector work
starts:

- Can this adapter produce canonical memory events with stable ids?
- What write/read/suppression/trusted-context capabilities does it actually
  expose?

## Non-Goals

- No real framework adapter.
- No memory scanning.
- No detector execution.
- No quarantine implementation.
- No trusted-read path.
- No enforce mode.
- No Mem0, Letta, Zep, Hermes, GBrain, LangChain, SQLite, or vector-store
  adapter claim.
- No release/tag/publish.

## Claim Budget

Allowed:

- Memory Firewall defines deterministic ids for adapter-emitted memory events.
- Memory Firewall defines a machine-readable adapter capability report.
- Memory Firewall can run a local conformance probe over its built-in fake
  adapter.

Not allowed:

- Memory Firewall supports real framework adapters today.
- Memory Firewall scans real stores today.
- Memory Firewall blocks or quarantines writes today.
- Memory Firewall proves an enforce path exists for any third-party memory
  system.

## Review Focus

- Are event ids stable and derived only from canonical event material?
- Are invalid and oversized adapter payloads rejected explicitly?
- Does the capability report avoid implying more support than the adapter has?
- Does the conformance runner fail non-canonical event ids?
- Does public language avoid scanner/enforcement/framework-adapter claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev python -m mypy --python-version 3.10 src/memory_firewall tests
uv run --python 3.11 --extra dev python -m mypy --python-version 3.11 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m mypy --python-version 3.12 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
git diff --check
uv run --python 3.12 --extra dev python -m build
uv run --python 3.12 --extra dev python -m twine check dist/*
```

## Local Gate Results

Passed on branch `codex/mf-02-adapter-contract` before draft PR creation:

- Python 3.12 tests: `31` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `memory-firewall doctor --json` passed with compatible
  `agent-memory-contracts` 1.3.x.
- `memory-firewall schema bundle` emitted the MF-02 schema bundle, including
  the adapter capability report schema.
- `memory-firewall conformance demo --json` passed and disclosed no complete
  enforce path.
- `git diff --check` passed.
- Build produced `memory_firewall-0.1.0.dev2` sdist and wheel in a temporary
  artifact directory.
- `twine check` passed for both artifacts.
- Installed-wheel smoke passed with `pip check`, `schema adapter`, and
  `conformance demo --json`.
