# MF-09 Reference Proxy

## Scope

This sprint adds the first adapter-shaped local reference substrate without
claiming support for any real memory framework:

- `SQLiteReferenceMemoryStore`;
- `ReferenceMemoryRecord`;
- `ProxyMode`;
- `ReferenceProxyWriteDecision`;
- `ReferenceProxyResult`;
- `reference_proxy_capability_report(...)`;
- `reference_proxy_demo_events(...)`;
- `run_reference_proxy(...)`;
- `memory-firewall proxy reference --mode observe|overlay|enforce`;
- `memory-firewall proxy reference --mode enforce --json`;
- `schema reference-proxy-result`;
- README, product-contract, claim-budget, and schema-bundle updates.

## Intent

MF-09 should move from "runnable poisoning demo" to "bounded adapter-shaped
reference flow":

```text
Observe preserves native writes. Overlay adds a separate governed context
preview. Enforce suppresses high-risk writes only inside the controlled
reference SQLite store.
```

## Non-Goals

- No Mem0, Hermes, GBrain, LangChain, Letta, Zep, vector-store, or production
  framework adapter.
- No hosted dashboard.
- No auth, billing, telemetry, or enterprise workflow.
- No benchmark or superiority claim.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No guarantee that native memory outside the reference SQLite substrate is
  secured.
- No release/tag/publish.
- No automatic LLM approval.
- No new `agent-memory-contracts` schema or ID semantics.

## Claim Budget

Allowed:

- Memory Firewall ships a custom SQLite reference proxy controlled by this
  package.
- The reference proxy supports explicit observe, overlay, and enforce modes.
- Observe mode preserves native writes while reporting scan/review outcomes.
- Overlay mode preserves native writes and exposes a separate governed context
  preview for clean pass records.
- Enforce mode suppresses high-risk writes inside the reference SQLite store.
- The reference proxy composes existing scan, review queue, and trusted-read
  preview surfaces.
- The reference proxy emits a capability report and validates through a
  machine-readable result schema.

Not allowed:

- Memory Firewall supports or wraps a real memory framework.
- Reference enforce mode proves production enforcement.
- Governed context preview is a trusted ledger, reducer decision, or production
  read broker.
- The reference proxy secures native memory outside the controlled SQLite
  substrate.
- The reference proxy is a benchmark.

## Review Focus

- Does the reference proxy compose existing scan/review/preview paths?
- Are observe, overlay, and enforce semantics explicit and test-covered?
- Does enforce suppress only inside the reference store?
- Does overlay preserve native writes while keeping governed context separate?
- Is the capability report honest and exhaustive?
- Are output and schema aligned?
- Are docs free of Mem0/Hermes/GBrain/LangChain/Letta/Zep/vector-store support
  claims?
- Are trusted ledger, reducer, hosted, and production enforcement claims avoided?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_proxy.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema reference-proxy-result
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode observe --json
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode overlay --json
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode enforce --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf09-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf09-dist/*
```

## Local Gate Results

Base before implementation:

- `origin/main`: `b275d88134088b78e2701f13c2a35dd71caa3f54`

Final local gates:

- focused MF-09/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_proxy.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `44` passed
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/proxy.py src/memory_firewall/reference_store.py src/memory_firewall/schema.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_proxy.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 8 source files`
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - `140` passed
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 31 source files`
- bytecode smoke:
  `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema reference-proxy-result`
  - `memory-firewall proxy reference --mode observe --json`
  - `memory-firewall proxy reference --mode overlay --json`
  - `memory-firewall proxy reference --mode enforce --json`
- proxy mode outcomes:
  - observe: native answer `Mirage`, governed context `null`, no suppressed
    native writes;
  - overlay: native answer `Mirage`, governed context `Helio`, no suppressed
    native writes;
  - enforce: native answer `Helio`, governed context `Helio`, one suppressed
    native write.
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf09-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf09-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev9-py3-none-any.whl` into
    `/tmp/memory-firewall-mf09-wheel-venv`;
  - installed console script smokes for `doctor`,
    `schema reference-proxy-result`, and proxy reference observe/overlay/enforce
    JSON modes;
  - wheel proxy outcomes matched source-tree outcomes;
  - `uv pip check` passed.

## Exact-Head Review

- Initial independent exact-head review by `Kierkegaard` on
  `23a3c2aae44477aa06f0b13a33df8fa7b031c38c` requested changes because
  caller-supplied `events=` could produce scan issues and return a
  schema-invalid proxy result with no write decisions.
- Fix-pass behavior: `run_reference_proxy(...)` now rejects scan-incompatible
  custom events before constructing a `ReferenceProxyResult`, with regression
  coverage.
- Final exact-head review: pending.

## Residual Risks

- This is a reference substrate, not a real external adapter.
- The governed context preview still is not a trusted ledger or reducer
  promotion.
- Real adapter work will need framework-specific write/read chokepoint proof
  before any enforce claim.
