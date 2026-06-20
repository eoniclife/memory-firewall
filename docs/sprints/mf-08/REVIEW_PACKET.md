# MF-08 Poisoning Lab

## Scope

This sprint adds a deterministic local demo that makes the memory-poisoning
failure mode runnable without adding real adapter or enforcement claims:

- `PoisonDemoScenario`;
- `NaiveMemoryWrite`;
- `NaiveMemoryRead`;
- `PoisonDemoResult`;
- `run_poison_demo(...)`;
- `memory-firewall demo poison`;
- `memory-firewall demo poison --json`;
- `schema demo-result`;
- README, product-contract, claim-budget, and schema-bundle updates.

## Intent

MF-08 should make the category line concrete:

```text
A prompt injection can end while its effect survives inside memory.
```

The acceptance test is:

```text
A toy last-write-wins memory store accepts a forged durable memory and later
answers the forged value; Memory Firewall flags the same forged write as
high-risk, queues it for review, and keeps it out of trusted-read preview unless
an explicit local override receipt exists.
```

## Non-Goals

- No real memory-store adapter.
- No Mem0, Letta, Zep, Hermes, GBrain, LangChain, SQLite, vector-store, or
  framework integration claim.
- No benchmark or superiority claim.
- No hosted demo.
- No HTML report.
- No native write suppression.
- No reference proxy or enforce mode.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No release/tag/publish.
- No automatic LLM approval.

## Claim Budget

Allowed:

- Memory Firewall ships a deterministic local poisoning demo.
- The demo uses normalized `MemoryEvent` records.
- The naive memory store is a toy last-write-wins store.
- The naive path can show the forged value after an untrusted overwrite.
- The Memory Firewall path composes the existing scan, review queue,
  allow/reject receipt, and trusted-read preview surfaces.
- Pending and rejected review items are excluded from trusted-read preview.
- The explicit override path requires a local allow receipt.
- The demo result validates against a machine-readable `demo-result` schema.

Not allowed:

- Memory Firewall wraps or supports a real memory framework.
- Memory Firewall blocks real writes.
- The demo proves universal poisoning detection.
- The demo is a benchmark.
- The toy store represents Mem0, Hermes, GBrain, LangChain, Letta, Zep, or any
  production memory substrate.
- An allow receipt proves objective truth.
- Trusted-read preview is a trusted ledger, reducer decision, or production
  read broker.

## Review Focus

- Does the demo compose the existing scan/review/preview path rather than
  creating a parallel judgment path?
- Does the naive path visibly return the forged value?
- Does the signed benign record pass and seed scan-local context?
- Does the untrusted overwrite become high-risk and enter the review queue?
- Are pending and rejected items excluded from preview?
- Does the explicit override preview require a receipt?
- Is output deterministic across repeated runs?
- Are schema and runtime output aligned?
- Do README, product contract, and claim budget avoid real adapter,
  enforcement, benchmark, and universal-detection claims?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_demo.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema demo-result
uv run --python 3.12 --extra dev memory-firewall demo poison --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf08-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf08-dist/*
```

## Local Gate Results

Base before implementation:

- `origin/main`: `6b3acc83d5c73f181121c34c93f6b65a13758ce3`

Initial focused gate:

- `uv run --python 3.12 --extra dev pytest tests/test_demo.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - failed because the first fixture used a payment-recipient memory; existing
    authority/payment detectors correctly marked the signed record high-risk,
    so the demo did not have exactly one queued item.
  - fixture was changed to a lower-risk signed project-codename fact so the
    first record passes and the untrusted overwrite becomes the single
    high-risk review item.

Final local gates:

- focused MF-08/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_demo.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `39` passed
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - `133` passed
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 28 source files`
- bytecode smoke:
  `uv run --python 3.12 --extra dev python -m compileall -q src tests`
- CLI/schema JSON smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema demo-result`
  - `memory-firewall demo poison --json`
  - demo outcome: naive answer `Mirage`, source-of-record answer `Helio`,
    one high-risk event, zero pending/rejected preview items, and one explicit
    override preview item with receipt.
- whitespace check:
  `git diff --check`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf08-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf08-dist/*`
- installed-wheel smoke:
  - first venv attempt used `python -m pip` in a uv-created venv without pip and
    failed before install;
  - rerun with `uv pip install --python /tmp/memory-firewall-mf08-wheel-venv/bin/python ...` passed;
  - installed console script smokes for `doctor`, `schema demo-result`, and
    `demo poison --json`;
  - wheel demo outcome matched source result;
  - `uv pip check` passed.

## Exact-Head Review

Pending.

## Residual Risks

- This is still a local demonstration, not an installable real-framework
  adapter.
- The demo depends on normalized event construction; real adapter value will
  require MF-09/MF-10 integration work.
- Detector and state-analysis output are review signals, not proof of
  adversarial intent or objective truth.
