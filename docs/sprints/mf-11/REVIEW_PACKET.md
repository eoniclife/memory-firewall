# MF-11 Hermes Hook Alpha

## Scope

This sprint adds the first real install-adjacent integration surface for Memory
Firewall:

- `memory_firewall.hermes`;
- `memory_firewall.hermes_plugin`;
- `memory-firewall hermes status`;
- `schema hermes-status`;
- a `hermes_agent.plugins` entry point named `memory-firewall`;
- local Hermes diagnostics JSONL for normalized events and observations;
- README, product contract, claim budget, and schema-bundle updates.

## Intent

MF-11 should let a Hermes user install Memory Firewall alongside their current
agent memory setup and see immediate local diagnostics when the agent attempts
to persist risky memory.

The product line is:

```text
Run this alongside your agent memory and see what risky memories are trying to
get written.
```

## Architecture Decision

Use a standalone Hermes hook plugin first, not a Hermes `MemoryProvider`.

Reasons:

- Hermes supports user/plugin hooks for `pre_tool_call`, `post_tool_call`, and
  `post_llm_call`.
- Hermes memory providers are single-select through `memory.provider`; a naive
  Memory Firewall provider would replace Mem0/Honcho instead of running
  alongside them.
- The first alpha should be observe-only and easy to dogfood before provider
  wrapping or enforcement semantics are attempted.

Private selection packet:

```text
/Users/a/Documents/AMC/amc-loop/ADAPTER_ALPHA_SELECTION.md
```

## Public Behavior

MF-11 observes:

- the built-in Hermes `memory` tool;
- obvious provider write tools such as `mem0_conclude` and `honcho_conclude`;
- obvious GBrain write tools such as `mcp__gbrain__put_page`;
- optional completed turns when `MEMORY_FIREWALL_HERMES_SCAN_TURNS=1`.

For observed write attempts, it:

- creates canonical `MemoryEvent` records;
- runs the existing local scan/detector/state-analysis path;
- appends local `events.jsonl` and `observations.jsonl`;
- summarizes local state through `memory-firewall hermes status`.

## Non-Goals

- No provider replacement.
- No Mem0/Honcho/GBrain API writes.
- No native memory suppression.
- No trusted ledger writes.
- No trusted context injection.
- No hosted dashboard or telemetry.
- No production enforcement claim.
- No release tag, PyPI publish, or external launch execution.

## Claim Budget

Allowed:

- Memory Firewall has an observe-only Hermes hook alpha.
- The alpha can normalize high-signal Hermes memory write attempts into
  `MemoryEvent` records.
- The alpha writes local JSONL diagnostics.
- `memory-firewall hermes status --json` summarizes local observations.
- Turn-level scanning for implicit provider writes is opt-in and may be noisy.

Not allowed:

- Memory Firewall secures Hermes memory.
- Memory Firewall replaces, wraps, or suppresses the active Hermes memory
  provider.
- Memory Firewall sees provider-internal `sync_turn` writes exactly.
- Hermes observations are trusted memory, reducer decisions, or ledger entries.
- The alpha supports all Hermes, GBrain, Mem0, Honcho, MCP, or framework memory
  behaviors.

## Review Focus

- Does the plugin remain fail-open so Hermes never breaks because Memory
  Firewall crashed?
- Does MF-11 avoid duplicate writes on both pre- and post-tool hooks?
- Are event normalization heuristics narrow enough to avoid claiming arbitrary
  tool observation as memory scanning?
- Does the CLI status output avoid raw trace leakage beyond the local
  diagnostics directory?
- Do docs and claim budget avoid provider replacement and enforcement claims?
- Does the entry point packaging match Hermes plugin discovery semantics?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/hermes_plugin.py src/memory_firewall/schema.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py
uv run --python 3.12 --extra dev pytest -q
UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema hermes-status
uv run --python 3.12 --extra dev memory-firewall hermes status --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf11-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf11-dist/*
```

## Local Gate Results

Base before implementation:

- `origin/main`: `456ed6db2c878d2dff80e0a900be1ad7e8961473`

Initial local gates:

- focused tests:
  `uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py -q`
  - fixed status-loader/path handling and CLI high-risk exit expectation;
  - final: `37` passed.
- focused mypy:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/hermes_plugin.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_hermes.py`
  - fixed test annotation/void-return hygiene;
  - final: `Success: no issues found in 5 source files`.

Expanded local gates:

- focused MF-11/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `52` passed.
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/hermes_plugin.py src/memory_firewall/schema.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 8 source files`.
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - passed for the collected `158` tests.
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
  - `memory-firewall schema hermes-status`
  - `memory-firewall hermes status --state-dir <empty-temp-dir> --json`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf11-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf11-dist/*`
  - wheel entry points include:
    - `memory-firewall = memory_firewall.cli:main`
    - `memory-firewall = memory_firewall.hermes_plugin` under
      `hermes_agent.plugins`.
- installed-wheel smoke:
  - created Python `3.12.11` venv with `uv venv`;
  - installed `memory_firewall-0.1.0.dev11-py3-none-any.whl`;
  - `memory-firewall --version` returned `0.1.0.dev11`;
  - `memory-firewall schema hermes-status` passed;
  - `memory-firewall hermes status --state-dir <empty-temp-dir> --json` passed;
  - `importlib.metadata.entry_points(group="hermes_agent.plugins")` found and
    loaded `memory_firewall.hermes_plugin`;
  - `uv pip check` passed.

PR URL, CI status, and exact-head review verdicts must be recorded before merge.

## Residual Risks

- A standalone hook cannot see provider-internal `sync_turn` writes exactly.
- Turn-level scanning is noisy and disabled by default.
- Concurrent gateway sessions may later need stronger file-locking or queue
  semantics once the diagnostics path becomes more than local dogfood.
- Enforcement belongs to a later provider-wrapper or policy-gate sprint.
