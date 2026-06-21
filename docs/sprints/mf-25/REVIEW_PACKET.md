# MF-25 Review Packet: Generic SQLite Write-Through Example

## Scope

Base main: `b4b38c26323ab6876b8155d1a2129d721ac97e5d`

MF-25 adds a copyable example for alpha users who already own a local Python
memory-write function:

- `examples/generic_write_through_sqlite.py` wraps a caller-owned SQLite writer
  with `observe_then_write_memory(...)`;
- the example writes benign, unknown-source, and injected-memory cases;
- native SQLite writes are preserved;
- a local generic adapter report bundle is generated;
- stdout contains only redacted observation summaries and report paths;
- README points users at the example and explains that the equivalent adapter
  report CLI exits `1` when high-risk rows are present;
- `MANIFEST.in` includes examples in the source distribution;
- tests run the example as a subprocess and leak-scan `redacted-share.json`.

## Non-Goals

- No Mem0, Honcho, GBrain, LangChain, Letta, Zep, Hermes, vector database, or
  production provider support claim.
- No provider replacement, wrapper, suppression, retry, approval, enforcement,
  trusted ledger writes, hosted dashboard, telemetry, release tag, PyPI publish,
  or external launch execution.
- No CLI that executes arbitrary shell memory-write commands.
- No public raw trace export.

## Reviewer Focus

Please review the exact PR head SHA only. A new push invalidates code approval.

Check especially:

- whether the example is genuinely provider-neutral and copyable;
- whether stdout or `redacted-share.json` can leak raw candidate text, raw event
  ids, writer return values, fake token values, or local coordinator paths;
- whether README or comments imply provider replacement, suppression, approval,
  enforcement, or framework-specific support;
- whether repeated example runs are safe for user-supplied workspaces;
- whether sdist inclusion and subprocess tests are enough for this docs/example
  surface.

## Local Gates

- `uv run --python 3.12 --extra dev pytest tests/test_examples.py -q` passed.
- Direct source example smoke passed:
  `uv run --python 3.12 --extra dev python examples/generic_write_through_sqlite.py --workspace <temp-workspace>`.
- Generated example `redacted-share.json` leak scan passed for raw candidate
  markers, fake writer token, raw event-id prefix, local coordinator paths, and
  private loop paths.
- `uv run --python 3.12 --extra dev pytest tests/test_examples.py tests/test_adapter_bridge.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  passed.
- `uv run --python 3.12 --extra dev python -m compileall -q src tests examples`
  passed.
- `git diff --check` passed.
- `uv run --python 3.12 --extra dev pytest -q` passed.
- `uv run --python 3.10 --extra dev mypy src tests` passed.
- `uv run --python 3.11 --extra dev mypy src tests` passed.
- `uv run --python 3.12 --extra dev mypy src tests` passed.
- `uv build --out-dir <temp-dist-dir>` passed.
- `uv run --python 3.12 --extra dev twine check <temp-dist-dir>/*` passed.
- Fresh installed-wheel smoke passed by installing
  `memory_firewall-0.1.0.dev23-py3-none-any.whl`, running the source example
  against that installed wheel, validating JSON output, validating generated
  redacted share JSON, and leak-scanning the redacted share.
- Source distribution includes `examples/generic_write_through_sqlite.py`.
- Public diff leak scan passed for local/private coordinator paths and ChatGPT
  URLs.
- independent exact-head review;
- PR CI green on the exact head SHA;
- main CI green after merge.
