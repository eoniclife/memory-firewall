# MF-04 Deterministic Detector Pack

## Scope

This sprint adds a deterministic local detector pack over one supplied
`MemoryEvent` JSON document.

Added:

- `DetectorDefinition`, `DetectorPack`, and `DetectorResult`;
- `default_detector_pack()` and `run_detectors(event)`;
- built-in deterministic detectors for provenance gaps, instruction-like
  persistence, authority/payment changes, stale temporal state, scope/privacy
  risk, secret-like content, and repeated sentence-like content;
- `memory-firewall detect --event <path> --json`;
- `memory-firewall schema detector-pack`;
- `memory-firewall schema detector-result`;
- detector schemas, CLI tests, detector tests, docs, and claim-budget updates.

## Intent

MF-04 should make the memory-integrity thesis runnable without pretending that
Memory Firewall can scan stores or enforce policy. A caller supplies a
canonical `MemoryEvent`; the built-in pack emits anchored `MemoryFinding`
objects plus deterministic policy recommendations.

## Non-Goals

- No real memory-store scanning.
- No file-system watch ingestion.
- No real framework adapter.
- No quarantine storage.
- No trusted-read path.
- No enforce mode.
- No hosted service.
- No release/tag/publish.
- No claim of semantic truth, adversarial intent, or universal poisoning
  detection.

## Claim Budget

Allowed:

- Memory Firewall runs deterministic local detectors over supplied
  `MemoryEvent` JSON.
- Detector findings are anchored to event text with structured evidence spans.
- Detector findings include explicit limitations and policy recommendations.

Not allowed:

- Memory Firewall scans real memory stores today.
- Memory Firewall proves a memory is false, malicious, poisoned, or safe.
- Memory Firewall blocks, quarantines, or enforces writes today.
- Memory Firewall supports real framework adapters today.

## Review Focus

- Are detector outputs deterministic for the same event?
- Do findings validate against the MF-04 schemas and the supplied event?
- Does every detector include explicit limitations?
- Does the benign fixture stay quiet?
- Do docs avoid scanner, quarantine, trusted-read, adapter, enforcement, and
  universal-poisoning claims?
- Is the CLI honest that it reads a supplied event JSON, not a memory store?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema detector-pack
uv run --python 3.12 --extra dev memory-firewall schema detector-result
uv run --python 3.12 --extra dev memory-firewall policy --json
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf04-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf04-dist/*
```

## Local Gate Results

Base before draft PR creation:

- `origin/main`: `dbc6956a93c9017911c1bbcbed2cb2254002b2d0`

Passed locally:

- focused detector/CLI/schema tests:
  `UV_PROJECT_ENVIRONMENT=.venv-312 uv run --python 3.12 --extra dev pytest tests/test_detectors.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `27` passed
- full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - `71` passed
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310 uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311 uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 20 source files`
- bytecode smoke:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema smokes with JSON validation:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema detector-pack`
  - `memory-firewall schema detector-result`
  - `memory-firewall policy --json`
  - `memory-firewall conformance demo --json`
  - `memory-firewall detect --event - --json`
- whitespace check:
  `git diff --check`
- package build:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv build --out-dir /tmp/memory-firewall-mf04-dist`
- package metadata:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf04-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev4-py3-none-any.whl` into
    `/tmp/memory-firewall-mf04-wheel-venv`
  - `uv pip check --python /tmp/memory-firewall-mf04-wheel-venv/bin/python`
  - installed console script smokes for `doctor`, detector schemas, and
    `detect --event - --json`

Reviewer and CI results are pending draft PR creation.
