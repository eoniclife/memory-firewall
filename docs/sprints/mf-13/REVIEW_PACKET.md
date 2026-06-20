# MF-13 Hermes Observation Report

## Scope

MF-13 makes the observe-only Hermes hook easier to dogfood after installation.

It adds:

- `memory-firewall hermes observations`;
- `memory-firewall hermes observations --json`;
- `memory-firewall schema hermes-observations`;
- redacted newest-first summaries over local Hermes diagnostics;
- README, product contract, claim budget, version, schema, and tests.

## Trigger

After MF-12 merged, local dogfood proved that Memory Firewall can be installed
into the user's Hermes environment, listed by Hermes' CLI, enabled, and loaded by
Hermes' runtime plugin manager. The remaining usability gap was that
`memory-firewall hermes status` showed aggregate counts only.

The user still needed a local way to answer:

```text
What did my agent try to remember, what risk did Memory Firewall see, and why
should I care?
```

## Public Behavior

The new command reads existing local diagnostics from:

```text
~/.hermes/memory-firewall/observations.jsonl
```

or from `--state-dir`.

It emits redacted rows with:

- row number;
- recorded time;
- hook name;
- tool name;
- redacted target namespace;
- local row handle;
- operation;
- source authority;
- level;
- highest disposition;
- finding count;
- contradiction count;
- risk categories;
- detector names.

It does not print raw candidate memory text or proposed memory text.

## Commands

```bash
memory-firewall hermes status --json
memory-firewall hermes observations --limit 20 --json
memory-firewall schema hermes-observations
```

## Non-Goals

- No Hermes core patch.
- No provider replacement.
- No Mem0/Honcho/GBrain write suppression.
- No trusted ledger writes.
- No trusted context injection.
- No hosted dashboard or telemetry.
- No production enforcement claim.
- No release tag, PyPI publish, or external launch execution.

## Review Focus

- Does `hermes observations` avoid printing raw/proposed memory content?
- Does the output give enough signal to understand recent Hermes memory risk?
- Are rows newest-first and correctly limited?
- Does the schema match the CLI JSON payload?
- Do docs avoid implying enforcement, provider wrapping, or raw trace export?
- Does the version/schema advance cleanly to MF-13?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/cli.py src/memory_firewall/schema.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py
uv run --python 3.12 --extra dev pytest -q
UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema hermes-observations
uv run --python 3.12 --extra dev memory-firewall hermes observations --state-dir <temp-dir> --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf13-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf13-dist/*
```

Dogfood should additionally verify that the installed package can record a
bounded Hermes observation in a temp state directory and then show it through the
new observations command without printing raw candidate memory text.

## Local Gate Results

- focused MF-13/Hermes/schema tests:
  `uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - initial: `59` passed;
  - fix-pass after exact-head review: `61` passed;
  - second fix-pass after timestamp / raw-derived ID review: `61` passed;
  - third fix-pass after strict timestamp-shape review: `61` passed.
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/cli.py src/memory_firewall/schema.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 7 source files`.
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - passed.
- full type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 36 source files`.
- bytecode and whitespace:
  - `uv run --python 3.12 --extra dev python -m compileall -q src tests`
  - `git diff --check`
- CLI/schema/Hermes smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema hermes-observations`
  - `memory-firewall hermes observations --state-dir <temp-dir> --json`
  - `memory-firewall hermes install-plugin --hermes-home <temp-dir> --json`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf13-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf13-dist/*`
  - sdist and wheel passed.
- installed-wheel smoke:
  - created Python `3.12.11` venv with `uv venv`;
  - installed `memory_firewall-0.1.0.dev13-py3-none-any.whl`;
  - `memory-firewall --version` returned `0.1.0.dev13`;
  - `memory-firewall schema hermes-observations` succeeded;
  - `memory-firewall hermes observations --state-dir <temp-dir> --json`
    succeeded for an empty diagnostics directory;
  - `memory-firewall hermes install-plugin --hermes-home <temp-dir> --json`
    wrote `plugin.yaml` and `__init__.py`;
  - installed distribution metadata exposed and loaded the
    `hermes_agent.plugins` entry point;
  - `uv pip check` passed.

## Review Fix-Pass

Independent exact-head reviewer `Ptolemy` requested changes on
`f373cdca2ca80ecfe6e55901ad8811af741052c5`:

- P1: redacted observations could leak raw candidate text through
  user-controlled `target_namespace` segments;
- P2: malformed or incomplete stored rows could produce CLI JSON that failed
  the exported schema, or crash on invalid JSON/non-`observe` mode values.

Fix-pass changes:

- redacts user-controlled memory and provider target namespace segments in
  `HermesObservationSummary`;
- preserves known safe namespace shape such as `hermes:memory:memory` and
  `hermes:provider-tool:<tool>`;
- normalizes malformed rows into schema-valid `warn` / `review` diagnostic
  summaries;
- skips invalid JSON crashes by creating a redacted diagnostic summary row;
- sanitizes tool, detector, timestamp, and identifier-like summary fields;
- exposes a local `event_ref` row handle instead of the raw-derived
  MemoryEvent ID in the redacted observations readout;
- adds regressions for secret-bearing targets, invalid JSON, incomplete rows,
  invalid enum values, malformed timestamps, and schema validation.

Second fix-pass changes after review of
`dd85abd13894d1aeb1b06b567ce3430cd5ddf8f5`:

- malformed or adversarial `recorded_at` values now collapse to
  `unavailable-recorded-at` instead of being echoed into summaries;
- Hermes status ignores malformed timestamps when calculating
  `latest_recorded_at`;
- redacted observation summaries use `event_ref: observation-row-N`, not a
  deterministic hash over raw/proposed memory content;
- text output prints detector names so a user can see why the row was flagged.

Third fix-pass changes after review of
`8b2d5c947e41b2925114fa798e1f5b8fdde4d587`:

- `recorded_at` now has to match the same RFC3339 timestamp pattern exported in
  the schemas before it can appear in observations or status output;
- Python-parseable but schema-invalid timestamp shapes such as
  `2026-06-20 15:00:00+00:00`, `2026-06-20T15:00:00+0000`, and
  `2026-W25-6T15:00:00+00:00` collapse to `unavailable-recorded-at`;
- status ignores those malformed timestamps rather than reporting them as
  `latest_recorded_at`.

Additional fix-pass probe:

- a secret-bearing `target` on both the built-in `memory` tool and a
  `mem0_remember` provider-like tool produced only
  `hermes:memory:redacted` and `hermes:provider-tool:mem0_remember:redacted`
  in the observations output;
- grep confirmed the secret phrase did not appear in the observations CLI JSON.
- an adversarial diagnostics row with a secret-bearing `recorded_at`,
  secret-bearing `target_namespace`, and raw MemoryEvent ID validated against
  both Hermes status and Hermes observations schemas without echoing the secret,
  timestamp phrase, or `mfev_v1_` ID in the redacted observations JSON.

## Dogfood Results

Local Hermes target:

- `Hermes Agent v0.16.0 (2026.6.5)`;
- runtime Python: `~/.hermes/hermes-agent/venv/bin/python`.

Observed with a temp diagnostics directory:

- Hermes runtime `PluginManager` loaded `memory-firewall` as enabled;
- registered hooks were `pre_tool_call`, `post_tool_call`, and `post_llm_call`;
- invoking Hermes' `post_tool_call` hook for a built-in `memory` write produced
  one high-risk observation;
- `memory-firewall hermes observations --state-dir <temp-dir> --limit 5 --json`
  returned one redacted row with:
  - `level`: `high_risk`;
  - `risk_categories`: `instruction_injection` and `provenance_gap`;
  - `raw_content_included`: `false`;
- grep confirmed the raw injected phrase was absent from the observations CLI
  JSON output;
- `memory-firewall hermes status --state-dir <temp-dir> --json` reported one
  high-risk observation;
- diagnostics permissions were verified:
  - state dir: `0700`;
  - `events.jsonl`: `0600`;
  - `observations.jsonl`: `0600`.

## Residual Risks

- The command is still a local diagnostic readout, not a polished UI.
- `observations.jsonl` itself may contain raw candidate memory text; only the
  readout is redacted.
- Runtime remains observe-only. Enforcement and provider wrapping remain later
  sprints.
