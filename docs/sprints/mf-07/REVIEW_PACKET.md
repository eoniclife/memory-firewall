# MF-07 Quarantine And Override

## Scope

This sprint adds a local review layer after MF-06 scan/watch:

- `ReviewQueue`;
- `ReviewItem`;
- `ReviewFindingSummary`;
- `OverrideDecision`;
- `OverrideReceipt`;
- `TrustedReadPreview`;
- `TrustedReadPreviewItem`;
- `enqueue_scan_result(...)`;
- `allow_review_item(...)`;
- `reject_review_item(...)`;
- `trusted_read_preview(...)`;
- `memory-firewall review enqueue <events.jsonl> --queue <queue.json>`;
- `memory-firewall review list --queue <queue.json>`;
- `memory-firewall review allow --queue <queue.json> --item-id <id> --reason <text>`;
- `memory-firewall review reject --queue <queue.json> --item-id <id> --reason <text>`;
- `memory-firewall review trusted-read-preview --queue <queue.json>`;
- `schema review-queue`;
- `schema override-receipt`;
- `schema trusted-read-preview`;
- README, product-contract, claim-budget, and schema-bundle updates.

## Intent

MF-07 makes high-risk scan output actionable without pretending to be a real
adapter gate.

The acceptance test is:

```text
High-risk scan events enter a deterministic local queue; explicit allow/reject
decisions create reasoned receipts; trusted-read preview includes allowed,
receipted assertions only.
```

## Non-Goals

- No hosted ingestion.
- No real framework adapter.
- No enterprise approval workflow or RBAC.
- No auth, billing, telemetry, or hosted dashboard.
- No reference proxy or enforce mode.
- No real memory-store scanning.
- No native write suppression.
- No `MemoryGate.promote` call.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No release/tag/publish.
- No automatic LLM approval.

## Claim Budget

Allowed:

- Memory Firewall can keep a local review queue of high-risk scan events.
- Review items are derived from `ScanEventResult` records, not raw invalid
  input lines.
- Local allow/reject decisions require non-empty reasons.
- Local override receipts are deterministic and bind the item hash.
- Repeating the same decision material is idempotent.
- Conflicting later decisions are rejected.
- Trusted-read preview includes allowed, receipted review items only.
- Rejected and pending items are excluded from preview items.

Not allowed:

- Memory Firewall quarantines or suppresses real memory writes.
- Memory Firewall approves trusted memory.
- Trusted-read preview is a trusted ledger, reducer decision, or production
  read broker.
- Allowing a review item proves objective truth.
- The local queue is an enterprise approval workflow.
- The queue connects to Mem0, Hermes, GBrain, LangChain, or any other real
  memory substrate.

## Review Focus

- Do high-risk scan events enter the queue deterministically?
- Are clean pass events skipped so the queue does not become review spam?
- Can rejected items leak into trusted-read preview?
- Are allow/reject receipts bound to immutable item hashes?
- Are repeated decisions either idempotent or explicitly rejected?
- Can raw invalid JSONL lines, raw secrets, or raw secret digests leak through
  queue files, receipts, or previews?
- Are schema and runtime output aligned?
- Do README, product contract, and claim budget avoid enforcement, real
  adapter, trusted ledger, and automatic approval claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_review.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema review-queue
uv run --python 3.12 --extra dev memory-firewall schema override-receipt
uv run --python 3.12 --extra dev memory-firewall schema trusted-read-preview
uv run --python 3.12 --extra dev memory-firewall review enqueue events.jsonl --queue review-queue.json --json
uv run --python 3.12 --extra dev memory-firewall review list --queue review-queue.json --json
uv run --python 3.12 --extra dev memory-firewall review allow --queue review-queue.json --item-id ITEM_ID --reason "verified locally" --json
uv run --python 3.12 --extra dev memory-firewall review reject --queue review-queue.json --item-id ITEM_ID --reason "does not match source of record" --json
uv run --python 3.12 --extra dev memory-firewall review trusted-read-preview --queue review-queue.json --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf07-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf07-dist/*
```

## Local Gate Results

Base before implementation:

- `origin/main`: `59658d235a9c02b1e0c0760c753030e8d7b34b83`

Initial focused gates:

- focused MF-07/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_review.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `40` passed
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/review.py src/memory_firewall/schema.py src/memory_firewall/cli.py tests/test_review.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 6 source files`
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - `127` passed
- final full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - passed before exact-head review fix-pass; `129` tests collected after the
    fix-pass
- bytecode smoke:
  `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 26 source files`
- CLI/schema JSON smokes:
  - `doctor --json`
  - `schema bundle`
  - `schema review-queue`
  - `schema override-receipt`
  - `schema trusted-read-preview`
- review queue CLI smoke:
  - generated a canonical two-line `MemoryEvent` JSONL stream;
  - `review enqueue` wrote one high-risk item to a local queue;
  - `review list` returned the pending item;
  - `review allow` emitted an allow receipt;
  - `review trusted-read-preview` returned one allowed preview item and
    `trusted_ledger_write = false`;
  - a separate `review reject` flow excluded the rejected item from preview.
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf07-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf07-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev7-py3-none-any.whl` into
    `/tmp/memory-firewall-mf07-wheel-venv`;
  - installed console script smokes for `doctor`, `schema review-queue`,
    `review enqueue`, `review allow`, and `review trusted-read-preview`;
  - trusted-read preview from the wheel returned one allowed preview item and
    `trusted_ledger_write = false`;
  - `uv pip check` passed.

## Exact-Head Review Fix Pass

Independent reviewer `Raman`
(`019ee690-c16d-76b3-86d0-14083c4d114c`) reviewed exact head
`51fa9ef6b099712aa8b21a28ddb77a7949f192e2` and requested changes.

Blocking finding:

- override receipts in a file-backed queue were bound to `item_id` and
  `item_hash_sha256`, but a tampered queue could recompute a deterministic
  receipt id with mismatched `event_id`, `assertion_id`, or `finding_ids`.
  `ReviewQueue.from_dict(...)` accepted that contradictory receipt and
  `trusted_read_preview(...)` could echo it.

Fix-pass changes:

- `ReviewQueue.__post_init__` now verifies receipt `event_id`,
  `assertion_id`, and `finding_ids` against the referenced review item;
- `TrustedReadPreviewItem.__post_init__` now verifies receipt `event_id` and
  `assertion_id` against the preview assertion;
- added regressions for tampered receipt side fields and preview receipt/event
  mismatch.

Fix-pass gates:

- focused MF-07/schema/CLI tests:
  `UV_PROJECT_ENVIRONMENT=.venv-312-focus uv run --python 3.12 --extra dev pytest tests/test_review.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `42` passed
- focused type checks:
  `UV_PROJECT_ENVIRONMENT=.venv-312-focus uv run --python 3.12 --extra dev mypy src/memory_firewall/review.py tests/test_review.py`
  - `Success: no issues found in 2 source files`
- full test suite:
  `UV_PROJECT_ENVIRONMENT=.venv-312-full uv run --python 3.12 --extra dev pytest -q`
  - passed with `129` tests collected
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 26 source files`
- bytecode smoke:
  `UV_PROJECT_ENVIRONMENT=.venv-312-compile uv run --python 3.12 --extra dev python -m compileall -q src tests`
- whitespace check:
  `git diff --check`

## Residual Risks

- This is still a local file-backed queue, not a production adapter gate.
- Decisions are operator overrides. They do not prove objective truth.
- The preview gives a useful local read surface, but it is not a trusted ledger
  write or reducer promotion.
