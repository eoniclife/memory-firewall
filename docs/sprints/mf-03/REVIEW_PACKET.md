# MF-03 Finding And Policy Model

## Scope

This sprint freezes deterministic finding and policy semantics before detector
execution starts.

Added:

- deterministic `MemoryFinding` ids derived from canonical finding material;
- structured `EvidenceSpan` model;
- event-anchored evidence span validation;
- policy ordering for severity and disposition;
- deterministic policy recommendation model;
- `memory-firewall schema evidence-span`;
- `memory-firewall schema policy`;
- `memory-firewall policy --json`.

## Intent

MF-03 should let later detectors emit reviewable findings with stable ids and
anchored evidence. It should also define deterministic recommendation semantics
without pretending that detectors, scanning, quarantine, or enforcement exist.

## Non-Goals

- No detector execution.
- No scan/watch ingestion.
- No real framework adapter.
- No quarantine storage.
- No trusted-read path.
- No enforce mode.
- No hosted service.
- No release/tag/publish.

## Claim Budget

Allowed:

- Memory Firewall defines deterministic ids for memory-integrity findings.
- Memory Firewall defines structured evidence spans that can be validated
  against supplied event text.
- Memory Firewall defines deterministic policy recommendation defaults.

Not allowed:

- Memory Firewall detects attacks today.
- Memory Firewall scans real stores today.
- Memory Firewall blocks, quarantines, or enforces writes today.
- Policy recommendations prove objective truth.
- Policy recommendations approve important memories automatically.

## Review Focus

- Are finding ids stable and derived only from canonical finding material?
- Are evidence spans structured and validated against event content?
- Are schema and Python model validation aligned?
- Are severity/disposition orderings deterministic and test-covered?
- Does the policy model avoid an opaque global score?
- Does public language avoid detector/scanner/quarantine/enforce claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev python -m mypy --python-version 3.10 src/memory_firewall tests
uv run --python 3.11 --extra dev python -m mypy --python-version 3.11 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m mypy --python-version 3.12 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema policy
uv run --python 3.12 --extra dev memory-firewall policy --json
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
git diff --check
uv run --python 3.12 --extra dev python -m build
uv run --python 3.12 --extra dev python -m twine check dist/*
```

## Local Gate Results

Passed on branch `codex/mf-03-finding-policy-model` before draft PR creation:

- Python 3.12 tests: `44` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `memory-firewall doctor --json` passed with compatible
  `agent-memory-contracts` 1.3.x.
- `memory-firewall schema bundle` emitted the MF-03 schema bundle.
- `memory-firewall schema policy` emitted the MF-03 policy schema.
- `memory-firewall policy --json` emitted deterministic default thresholds and
  ordering.
- `memory-firewall conformance demo --json` passed.
- `git diff --check` passed.
- Build produced `memory_firewall-0.1.0.dev3` sdist and wheel in a temporary
  artifact directory.
- `twine check` passed for both artifacts.
- Installed-wheel smoke passed with `pip check`, `schema policy`,
  `policy --json`, and `conformance demo --json`.

Fix-pass after self-review:

- Tightened runtime/schema parity for numeric policy and finding fields:
  `MemoryFinding.confidence` and `PolicyConfig` thresholds now reject booleans
  and numeric strings instead of coercing them.
- Tightened `PolicyRecommendation.reason_codes` so empty reason codes are
  rejected consistently with the exported schema.
- Added focused regression coverage for those parity checks.
- Python 3.12 tests now pass with `49` tests.
- mypy still passes for Python `3.10`, `3.11`, and `3.12`.
- `compileall`, `doctor --json`, `schema bundle`, `schema policy`,
  `policy --json`, `conformance demo --json`, `git diff --check`, build,
  `twine check`, and installed-wheel smoke all pass after the fix-pass.
