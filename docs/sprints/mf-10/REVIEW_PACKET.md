# MF-10 Report And Release-Readiness

## Scope

This sprint adds the local report and redacted export surface needed for a
credible public alpha without executing a release:

- `ReportSummary`;
- `ReportEventSummary`;
- `ReportResult`;
- `ReportBundle`;
- `RedactedReportExport`;
- `generate_demo_report(...)`;
- `redact_report_export(...)`;
- `render_report_html(...)`;
- `write_report_bundle(...)`;
- `ReportBundle.to_dict()` as a redacted, paths-only bundle summary;
- `memory-firewall report demo --out <dir> --json`;
- `schema report-result`;
- `schema redacted-report-export`;
- issue templates for adapter requests, false positives, detector suggestions,
  and redacted report feedback;
- README, product-contract, claim-budget, and schema-bundle updates.

## Intent

MF-10 should make the artifact easier to try and easier to discuss:

```text
Run the poisoning demo, run the reference proxy, write a local report, and share
only redacted feedback by default.
```

## Non-Goals

- No hosted dashboard.
- No server process.
- No auth, billing, telemetry service, or enterprise workflow.
- No real Mem0, Hermes, GBrain, LangChain, Letta, Zep, vector-store, or
  production framework adapter.
- No trusted ledger entry, state snapshot, or reducer decision write.
- No production enforcement claim.
- No release tag, PyPI publish, or external launch execution.
- No raw-content sharing by default.
- No new `agent-memory-contracts` schema or ID semantics.

## Claim Budget

Allowed:

- Memory Firewall generates a local static report over its deterministic demo
  and reference proxy surfaces.
- The report command writes `report.json`, `index.html`, and
  `redacted-share.json`.
- The redacted share export omits raw content, answer values, event IDs,
  source IDs, review item IDs, and receipt IDs by default.
- The default bundle serialization is redacted/paths-only; the full local
  report remains explicit through `report.json` or `bundle.report.to_dict()`.
- The report exposes aggregate findings, proxy-mode outcomes, suppressed-write
  counts, and capability boundaries.
- Issue templates collect adapter requests and redacted feedback.

Not allowed:

- Memory Firewall ships a hosted dashboard.
- Memory Firewall sends telemetry or uploads reports.
- Redacted export is a raw trace export.
- The local report proves objective truth, production enforcement, or universal
  poisoning detection.
- This PR releases, tags, publishes, or externally launches the package.

## Review Focus

- Does the report compose existing demo/proxy/scan paths rather than creating a
  parallel judgment path?
- Does the redacted export remove raw content, answer values, stable event IDs,
  source IDs, review item IDs, and receipt IDs?
- Are report and redacted-export schemas aligned with runtime output?
- Does the CLI write deterministic local files without network access?
- Does the easy Python bundle serialization avoid carrying the full local
  report by default?
- Do docs avoid hosted dashboard, release/publish, real adapter, and production
  enforcement claims?
- Are issue templates safe for users to file without leaking raw traces?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_report.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev mypy src tests
uv run --python 3.11 --extra dev mypy src tests
uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema report-result
uv run --python 3.12 --extra dev memory-firewall schema redacted-report-export
uv run --python 3.12 --extra dev memory-firewall report demo --out /tmp/memory-firewall-mf10-report --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf10-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf10-dist/*
```

## Local Gate Results

Base before implementation:

- `origin/main`: `20b8b61e3d2978877208d9d580819563e9fe14d2`

Final local gates:

- focused MF-10/schema/CLI tests:
  `uv run --python 3.12 --extra dev pytest tests/test_report.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - initial: `45` passed
  - fix-pass: `47` passed
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/report.py src/memory_firewall/schema.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_report.py tests/test_cli.py tests/test_schema_and_taxonomy.py`
  - `Success: no issues found in 7 source files`
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - initial: `146` passed
  - fix-pass: `148` passed
- type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 33 source files`
- bytecode and whitespace:
  - `uv run --python 3.12 --extra dev python -m compileall -q src tests`
  - `git diff --check`
- CLI/schema/report smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall schema report-result`
  - `memory-firewall schema redacted-report-export`
  - `memory-firewall report demo --out /tmp/memory-firewall-mf10-report --json`
- redaction audit:
  - CLI JSON stdout and `redacted-share.json` omitted `Helio`, `Mirage`,
    `mfev_v1_`, `mfrevitem_v1_`, `mfreceipt_v1_`, `chat:attacker-note`, and
    `registry:project`;
  - fix-pass CLI JSON stdout also omits the local output directory path and
    reports only filenames plus `paths_redacted: true`;
  - local `report.json` and `index.html` may contain local demo answer values,
    but the generated share/export path does not.
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf10-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf10-dist/*`
- installed-wheel smoke:
  - installed `memory_firewall-0.1.0.dev10-py3-none-any.whl` into
    `/tmp/memory-firewall-mf10-wheel-venv`;
  - installed console script smokes for `doctor`, `schema bundle`,
    `schema report-result`, `schema redacted-report-export`, and
    `report demo`;
  - installed-wheel CLI JSON stdout and `redacted-share.json` passed the same
    forbidden-token redaction audit;
  - `uv pip check` passed.

## Exact-Head Review

Initial independent reviewer `Locke`
(`019ee6db-ab59-7ae0-9996-a83db35ecf21`) found:

- P1: `RedactedReportExport` accepted arbitrary mappings and could serialize
  schema-invalid/unredacted keys through the public API.
- P2: `ReportSummary` accepted claim flags that violated the schema constants.
- P2: `ReportBundle.to_dict()` and CLI `--json` included absolute local file
  paths.

Fix-pass response:

- `RedactedReportExport` now requires exact redacted mapping keys for demo
  outcome, proxy outcomes, and event summaries, and validates redaction flags.
- `ReportSummary` now enforces `redacted_share_default is True`,
  `hosted_dashboard is False`, and `production_adapter_support is False`.
- `ReportBundle.to_dict()` and CLI `--json` now emit filename-only file
  metadata with `paths_redacted: true`.
- Regression tests cover all three findings.

Final exact-head review after fix-pass: pending.

## Residual Risks

- This is a local report over deterministic demo/reference paths, not a real
  external memory-system report.
- The report is useful for alpha feedback, but real adapter requests still need
  traces and framework-specific chokepoint proof.
- Actual release/tag/publish is deliberately outside this PR.
