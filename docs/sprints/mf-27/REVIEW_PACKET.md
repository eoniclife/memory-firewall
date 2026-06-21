# MF-27 Review Packet: Stage-Aware Memory Lineage

## Scope

Base main: `ab51d66ff1e0f3643a20dac2d2bad9119e4984ee`

MF-27 adds a bounded candidate-level lineage surface:

- `src/memory_firewall/lineage.py` models source, extracted-candidate,
  Memory Firewall scan, persisted-memory, and retrieved-memory evidence stages;
- `generate_lineage_report(...)` links candidates to persisted and retrieved
  records by provider memory id plus exact content digest, persisted id plus
  exact content digest, or unique content digest with explicit weaker-confidence
  limitations;
- the report emits per-candidate verdicts including persisted status, retrieved
  status, downstream-use status, Memory Firewall event id, disposition, finding
  count, scan status, persisted-link status, and retrieval-link status;
- `memory-firewall lineage report <path> --json` prints the report and exits
  nonzero when unresolved lineage issues remain;
- `memory-firewall schema lineage-report` exposes the MF-27 report schema;
- tests cover the exact WP-03A senior-review problem where a sibling candidate
  is quarantined but the downstream-used candidate is only warned.

## Why

The WP-03A senior review found that case-level maximum disposition can make a
packet look stronger than it is. MF-27 prevents that by forcing evidence packets
to answer:

- Which exact memory drove the answer?
- What was its provider memory id?
- Which source event produced it?
- Did Memory Firewall scan that exact text?
- What disposition applied to that exact candidate?
- Was a sibling memory, rather than the influential memory, the quarantined item?

## Non-Goals

- No live Mem0, Honcho, GBrain, Hermes, LangChain, Letta, Zep, SQLite, vector
  database, or production provider adapter.
- No write suppression, retry, approval, enforcement, trusted ledger,
  dashboard, hosted telemetry, release tag, PyPI publish, or external launch.
- No new semantic detector.
- No claim of verified provenance. The report reflects supplied evidence and
  explicitly marks weak digest-only links, case-level-only scans, scope
  mismatches, unmatched persisted records, and unmatched retrievals.

## Reviewer Focus

Please review the exact PR head SHA only. A new push invalidates approval.

Check especially:

- whether candidate-level verdicts can no longer be confused with case-level
  maximum disposition;
- whether digest-only linking is clearly marked as weaker than provider-id
  linking;
- whether scan records must match candidate id, digest, and scope before a
  candidate-level Memory Firewall disposition is reported;
- whether provider-id matches also require exact content-digest agreement;
- whether downstream-used candidates without candidate-level scan verdicts are
  surfaced as issues;
- whether scope mismatches, mutated persisted text, and orphan retrievals are
  caught;
- whether duplicate IDs/digests and reused local IDs across lineages avoid
  arbitrary last-record-wins behavior;
- whether CLI/schema/docs avoid implying live provider support, write
  suppression, enforcement, or verified provenance.

## Local Gates

- `uv run --python 3.12 --extra dev pytest tests/test_lineage.py tests/test_cli.py -q`
  passed.
- `uv run --python 3.12 --extra dev pytest -q` passed.
- `uv run --python 3.12 --extra dev mypy src tests` passed.
- `UV_PROJECT_ENVIRONMENT=.venv310 uv run --python 3.10 --extra dev pytest -q`
  passed.
- `UV_PROJECT_ENVIRONMENT=.venv311 uv run --python 3.11 --extra dev pytest -q`
  passed.
- `UV_PROJECT_ENVIRONMENT=.venv310-mypy uv run --python 3.10 --extra dev mypy src tests`
  passed.
- `UV_PROJECT_ENVIRONMENT=.venv311-mypy uv run --python 3.11 --extra dev mypy src tests`
  passed.
- `uv run --python 3.12 --extra dev python -m compileall -q src tests` passed.
- `git diff --check` passed.
- `uv run --python 3.12 --extra dev memory-firewall schema lineage-report |
  python3 -m json.tool` passed.
- `UV_PROJECT_ENVIRONMENT=.venv312-build uv run --python 3.12 --extra dev python -m build --outdir <temp-dist-dir>`
  passed.
- `UV_PROJECT_ENVIRONMENT=.venv312-build uv run --python 3.12 --extra dev twine check <temp-dist-dir>/*`
  passed.
- Installed-wheel smoke on Python 3.12 passed:
  `memory-firewall schema lineage-report` rendered valid JSON and importing
  `LINEAGE_VERSION` / `lineage_report_schema` from the wheel succeeded.
