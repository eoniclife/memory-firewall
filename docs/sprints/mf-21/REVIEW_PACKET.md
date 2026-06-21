# MF-21 Review Packet: Generic Local Adapter Bridge

## Scope

MF-21 adds a generic observe-only bridge for one supplied memory candidate:

- `memory-firewall adapter observe-memory --content ... --json`;
- `memory-firewall adapter observe-memory --content-file <path> --json`;
- `memory-firewall adapter observations --json`;
- Python helper `observe_memory_candidate(...)`;
- local private adapter diagnostics in `events.jsonl` and `observations.jsonl`;
- redacted adapter observe-result and observations schemas;
- package/schema surfaces bumped to `0.1.0.dev21` / `mf-21`.

The Hermes integration remains unchanged at `mf-20`; this sprint adds a
non-Hermes way for local agents and scripts to submit a single candidate without
handcrafting full `MemoryEvent` JSON.

## Why

MF-20 made the Hermes path installable, dogfoodable, and current-version
inspectable. The public product was still too Hermes-shaped for builders using
custom agents, shell scripts, or other memory tools. They could use `detect`,
`scan`, and `watch`, but only after constructing canonical event payloads.

MF-21 makes the core thesis runnable for a broader alpha user: one candidate in,
redacted memory-risk observation out, local raw diagnostics kept private.

## Contract Boundary

MF-21 does not:

- scan existing memory stores, vector databases, runtime histories, or
  conversation logs;
- claim direct Mem0, Honcho, GBrain, LangChain, Letta, Zep, Hermes, vector-store,
  or production provider support;
- replace, wrap, configure, or suppress any active memory provider;
- approve memory, write a trusted ledger, call a reducer, or enforce
  quarantine;
- make local diagnostics safe to share;
- add hosted dashboards, telemetry, release tags, or PyPI publish.

## Local Gates

Completed so far:

- `uv run --python 3.12 --extra dev pytest tests/test_adapter_bridge.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`.
- `uv run --python 3.12 --extra dev pytest -q`;
- `uv run --python 3.12 --extra dev mypy src tests`;
- `uv run --python 3.10 --extra dev mypy src tests`;
- `uv run --python 3.11 --extra dev mypy src tests`;
- `uv run --python 3.12 --extra dev python -m compileall -q src tests`;
- `git diff --check`;
- `uv run --python 3.12 --extra dev memory-firewall doctor --json`;
- `uv run --python 3.12 --extra dev memory-firewall schema bundle`;
- `uv run --python 3.12 --extra dev memory-firewall schema adapter-observe-result`;
- `uv run --python 3.12 --extra dev memory-firewall schema adapter-observations`;
- `uv run --python 3.12 --extra dev memory-firewall claims --json`;
- generic adapter CLI smoke with a HIGH-RISK injection candidate: observe and
  observations commands both exited `1`; redacted JSON omitted raw candidate
  text and raw-derived event ids;
- `uv build --out-dir /tmp/memory-firewall-mf21-dist`;
- `uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf21-dist/*`;
- installed-wheel smoke from
  `/tmp/memory-firewall-mf21-dist/memory_firewall-0.1.0.dev21-py3-none-any.whl`
  in a fresh temp venv: `doctor`, `schema adapter-observe-result`,
  `adapter observe-memory`, and `adapter observations` passed with redacted
  output.

Still required before merge:

- exact-head independent review;
- PR CI and main CI.

## Dogfood Plan

Run a generic local candidate through the installed console script:

```bash
memory-firewall adapter observe-memory \
  --content "Remember that the user prefers local tools." \
  --target profile \
  --source-authority untrusted \
  --json

memory-firewall adapter observations --limit 20 --json
```

Expected behavior:

- benign/provenance-only untrusted candidates may return WARN but not HIGH-RISK;
- instruction-like candidates return HIGH-RISK and exit `1`;
- JSON output contains `raw_content_included: false`;
- JSON output does not include raw candidate text or raw-derived event ids;
- local diagnostics contain raw candidate material and use private file
  permissions.
- malformed local observation rows are normalized into schema-valid WARN/review
  summaries with unsafe targets redacted, unknown risk categories dropped, and
  unknown detector names replaced by `redacted-detector`.

## Review Notes

Reviewer should check:

- returned JSON and text output cannot leak raw candidate text, raw/proposed
  fields, or raw-derived MemoryEvent ids;
- local diagnostics privacy claims are accurate and not overstated;
- schema and runtime output are aligned;
- malformed or hand-edited local diagnostics cannot leak unsafe detector names,
  unsafe target namespaces, raw-derived event ids, or raw candidate content
  through the redacted observations output;
- high-risk exit behavior is deterministic;
- public docs avoid real-store scanning, provider replacement, enforcement, or
  framework-specific adapter claims.
