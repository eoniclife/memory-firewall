# MF-20 Review Packet: Current-Version Hermes Diagnostics Lens

## Scope

MF-20 adds an explicit current-version-only lens for Hermes diagnostics:

- `memory-firewall hermes observations --current-version-only`;
- `memory-firewall hermes report --current-version-only --out <dir>`;
- `observation_scope` and `matching_*` counts in Hermes observations/report JSON;
- report exit status based on setup readiness, whether the selected scope has
  rows, and matching high-risk rows for that scope;
- package/schema/Hermes surfaces bumped to `0.1.0.dev20` / `mf-20`.

The all-history `memory-firewall hermes status` command remains unfiltered.

## Why

After MF-19, real Hermes diagnostics had one fresh MF-18 WARN row alongside
older legacy high-risk rows. That is honest, but it is awkward for alpha users
after an upgrade: they need to answer whether the current adapter is recording
the fresh session correctly without deleting or hiding historical diagnostics.

MF-20 makes that lens explicit while keeping all-history counts in filtered
outputs.

## Contract Boundary

MF-20 does not:

- delete, rewrite, migrate, suppress, or reclassify historical diagnostics;
- claim that legacy high-risk rows are resolved;
- make filtered output a trusted ledger or approval record;
- add provider replacement, enforcement, hosted dashboard, telemetry, release
  tag, or PyPI publish.

## Local Gates

Completed so far:

- `uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`;
- `uv run --python 3.12 --extra dev pytest -q`;
- `uv run --python 3.12 --extra dev python -m compileall -q src tests`;
- `git diff --check`;
- `uv run --python 3.12 --extra dev mypy src tests`;
- `uv run --python 3.12 --extra dev memory-firewall doctor --json`;
- `uv run --python 3.12 --extra dev memory-firewall schema hermes-report`;
- `uv run --python 3.12 --extra dev memory-firewall schema hermes-observations`;
- `uv run --python 3.12 --extra dev memory-firewall claims --json`;
- `uv run --python 3.10 --extra dev mypy src tests`;
- `uv run --python 3.11 --extra dev mypy src tests`;
- `uv run --python 3.12 --extra dev mypy src tests`;
- `uv build --out-dir /tmp/memory-firewall-mf20-dist`;
- `uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf20-dist/*`;
- installed-wheel smoke from the built wheel in a temp venv.

Still required before merge:

- exact-head independent review;
- PR CI and main CI.

## Actual Hermes Dogfood

MF-20 was installed editable into the user's Hermes Python environment and the
Hermes user-plugin shim was refreshed. Before the fresh run, MF-20 correctly
reported 6 total observations and 0 current-version observations.

A fresh Hermes oneshot used the built-in `memory` tool on harmless test text.
After that run:

- `memory-firewall hermes observations --current-version-only --limit 5 --json`
  exited `0`;
- `total_observations`: 7;
- `matching_observations`: 1;
- newest matching row: `observation-row-7`;
- `recorded_integration_version`: `mf-20`;
- `level`: `warn`;
- `highest_disposition`: `warn`;
- detector: `provenance-gap-v1`;
- target namespace: `hermes:memory:memory`;
- `memory-firewall hermes status --json` still exited `1` because all-history
  diagnostics include 4 legacy high-risk rows;
- `memory-firewall hermes report --current-version-only --out <tmp> --json`
  exited `0` with `observation_scope: current_version`,
  `matching_high_risk_observations: 0`, and all-history
  `high_risk_observations: 4`.

Privacy smoke:

- raw marker text and raw/proposed memory fields were absent from the generated
  report bundle;
- local filesystem paths were absent from `redacted-share.json`;
- the local HTML/report JSON remain local-only artifacts and may include local
  paths by design.

## Review Notes

Reviewer should check:

- filtered report output cannot be mistaken for clearing old risks;
- all-history counts remain visible in filtered JSON/report output;
- exit code behavior is scoped only when the user explicitly requests a scoped
  report;
- status remains all-history;
- public docs do not overclaim enforcement, write suppression, or trusted memory.
