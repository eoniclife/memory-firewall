# MF-22 Review Packet: Generic Adapter Report

## Scope

Base main: `4fffc478093c9399b6732fe09a7e08f314cc0ba0`

MF-22 extends the generic adapter bridge from a one-candidate observe/readout
surface into a local static report surface:

- package/schema surfaces move to `0.1.0.dev22` / `mf-22`;
- `memory-firewall adapter report --out <dir> [--open] [--json]` writes a local
  report over existing generic adapter observations;
- report bundle files are `report.json`, `index.html`, and
  `redacted-share.json`;
- report JSON includes setup status, all-history observation and
  level/risk/detector counts, recent redacted rows, next steps, and limitations;
- redacted share export removes local filesystem paths and keeps raw candidate
  content and raw-derived event ids out of the share artifact;
- `memory-firewall schema adapter-report` and the schema bundle expose the new
  contract;
- Python helpers `generate_adapter_report(...)`, `render_adapter_report_html(...)`,
  and `write_adapter_report_bundle(...)` are exported.

## Non-Goals

- No broad real memory-store scanning.
- No Mem0, Honcho, GBrain, LangChain, Letta, Zep, Hermes, vector database, or
  production provider support claims for the generic bridge.
- No provider replacement, wrapper, suppression, quarantine enforcement, trusted
  ledger writes, reducer approval, hosted dashboard, telemetry, release tag,
  PyPI publish, or external launch execution.
- No raw trace export. Local diagnostics JSONL may contain raw candidate text;
  CLI/report readouts must not.

## Reviewer Focus

Please review the exact PR head SHA only. A new push invalidates code approval.

Check especially:

- redaction: raw candidate text, raw/proposed fields, raw event ids, unsafe
  target namespaces, corrupt raw JSONL lines, and local paths must not appear in
  CLI JSON or `redacted-share.json`;
- report exit behavior: high-risk generic observations return non-zero; WARN-only
  diagnostics, including corrupt JSONL diagnostic rows, remain review signals
  without failing the report;
- schema honesty: `adapter-report` matches the report payload and the schema
  bundle version;
- public claim honesty: README, product contract, and claim budget do not imply
  real-store scanning, provider support, approval, suppression, enforcement, or
  hosted monitoring;
- compatibility: existing adapter observe/observations, Hermes, demo report, and
  schema commands still work.

## Initial Review Findings

Independent reviewer James rejected initial head
`0a58e6ef19ff2a7a61b656a5a2ff67f89263daf4` with:

- P2: token-shaped `adapter_name` / `recorded_bridge_version` metadata could
  leak into `redacted-share.json`;
- P3: report aggregate counts were computed over the returned `--limit` window,
  so an older high-risk row could make the report exit non-zero while the report
  displayed only PASS-level counts.

The fix-pass:

- added stricter public scrubbing for adapter labels and recorded bridge
  versions;
- added redaction regressions for token-shaped adapter names;
- made report level/risk/detector counts all-history counts while the row table
  remains limited;
- changed high-risk next-step guidance to use a limit large enough to reveal the
  full local history;
- documented the all-history count / limited-row split.

## Local Gates

Passed before opening the PR:

- `uv run --python 3.12 --extra dev pytest tests/test_adapter_bridge.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
- `uv run --python 3.12 --extra dev pytest -q`
- `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- `uv run --python 3.10 --extra dev mypy src tests`
- `uv run --python 3.11 --extra dev mypy src tests`
- `uv run --python 3.12 --extra dev mypy src tests`
- `git diff --check`
- `uv run --python 3.12 --extra dev memory-firewall doctor --json`
- `uv run --python 3.12 --extra dev memory-firewall schema bundle`
- `uv run --python 3.12 --extra dev memory-firewall schema adapter-report`
- `uv run --python 3.12 --extra dev memory-firewall claims --json`
- temp CLI smoke:
  `adapter observe-memory` with a high-risk candidate returned `1`,
  `adapter report` returned `1`, wrote `report.json`, `index.html`, and
  `redacted-share.json`, and the share export omitted the raw marker and
  `mfev_v1_` ids;
- `uv build --out-dir <temp-dist-dir>`
- `uv run --python 3.12 --extra dev twine check <temp-dist-dir>/*`
- installed-wheel smoke from the built `0.1.0.dev22` wheel for `doctor`,
  `schema adapter-report`, `adapter observe-memory`, and `adapter report`.

Passed again after the fix-pass:

- `uv run --python 3.12 --extra dev pytest tests/test_adapter_bridge.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
- `uv run --python 3.12 --extra dev pytest -q`
- `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- `uv run --python 3.10 --extra dev mypy src tests`
- `uv run --python 3.11 --extra dev mypy src tests`
- `uv run --python 3.12 --extra dev mypy src tests`
- `git diff --check`
- doctor/schema/claims smokes;
- temp CLI smoke for token-shaped adapter-name redaction in
  `adapter observe-memory` + `adapter report`;
- `uv build --out-dir <temp-dist-dir>`
- `uv run --python 3.12 --extra dev twine check <temp-dist-dir>/*`
- installed-wheel smoke from the fix-pass `0.1.0.dev22` wheel for `doctor`,
  `schema adapter-report`, `adapter observe-memory`, and `adapter report`.

Pending after PR creation:

- independent exact-head re-review of the fix-pass head;
- PR CI green on the fix-pass exact head SHA;
- main CI green after merge.
