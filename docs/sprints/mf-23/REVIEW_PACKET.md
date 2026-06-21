# MF-23 Review Packet: Generic Write-Through Helper

## Scope

Base main: `6f418b47b57684305897e7722e7a9b2b518f8fa3`

MF-23 adds a small in-process Python helper for custom agents that already own a
memory-write function:

- package/schema surfaces move to `0.1.0.dev23` / `mf-23`;
- `observe_then_write_memory(...)` observes one supplied candidate, then calls a
  caller-supplied `write_candidate(content)` callback;
- the helper returns a redacted `AdapterBridgeWriteThroughResult`;
- writer return values are discarded and never included in result payloads;
- writer failures re-raise by default to preserve caller semantics;
- callers can opt into `raise_writer_errors=False` to receive a redacted failure
  result containing exception type only, not exception message;
- token/secret-looking adapter and writer labels are redacted in public result
  payloads;
- `memory-firewall schema adapter-write-through-result` and the schema bundle
  expose the helper result contract;
- README/product contract/claim budget include a minimal Python integration
  path and explicit non-claims.

## Non-Goals

- No CLI that executes arbitrary shell memory-write commands.
- No broad real memory-store scanning.
- No Mem0, Honcho, GBrain, LangChain, Letta, Zep, Hermes, vector database, or
  production provider support claim for the generic helper.
- No provider replacement, wrapper, suppression, retry, approval, enforcement,
  trusted ledger writes, hosted dashboard, telemetry, release tag, PyPI publish,
  or external launch execution.
- No raw writer return export and no exception-message export.

## Reviewer Focus

Please review the exact PR head SHA only. A new push invalidates code approval.

Check especially:

- whether `observe_then_write_memory(...)` can leak raw candidate text, raw event
  ids, writer return values, exception messages, unsafe adapter labels, or unsafe
  writer labels into returned JSON;
- whether writer failure behavior preserves default caller semantics by
  re-raising unless `raise_writer_errors=False`;
- whether the helper accidentally implies enforcement, approval, suppression,
  retry, provider wrapping, or framework-specific support;
- whether schema bundle/CLI schema output match the new result payload;
- whether existing adapter observe/observations/report and Hermes surfaces still
  work.

## Local Gates

- `uv run --python 3.12 --extra dev pytest tests/test_adapter_bridge.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  passed.
- `uv run --python 3.12 --extra dev pytest -q` passed.
- `uv run --python 3.12 --extra dev python -m compileall -q src tests`
  passed.
- `uv run --python 3.10 --extra dev mypy src tests` passed.
- `uv run --python 3.11 --extra dev mypy src tests` passed.
- `uv run --python 3.12 --extra dev mypy src tests` passed.
- `git diff --check` passed.
- Doctor, schema bundle, `schema adapter-write-through-result`,
  `schema adapter-report`, and `claims --json` smokes emitted valid JSON.
- Editable-tree Python smoke validated `observe_then_write_memory(...)` against
  the exported JSON schema and checked that raw candidate text, raw event ids,
  and writer return values are absent from the returned payload.
- `uv build --out-dir <temp-dist-dir>` passed.
- `uv run --python 3.12 --extra dev twine check <temp-dist-dir>/*` passed.
- Installed-wheel smoke from
  `memory_firewall-0.1.0.dev23-py3-none-any.whl` passed for `--version`,
  `doctor --json`, `schema adapter-write-through-result`, and an in-process
  `observe_then_write_memory(...)` call with no raw candidate, raw event id, or
  writer return leakage in the result payload.
- Public diff leak scan for local/private coordinator paths and ChatGPT URLs
  passed.
- independent exact-head review;
- PR CI green on the exact head SHA;
- main CI green after merge.
