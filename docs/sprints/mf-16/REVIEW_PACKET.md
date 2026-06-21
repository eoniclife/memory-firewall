# MF-16 Hermes Diagnostics Report

## Scope

MF-16 adds a local redacted report over existing Hermes Memory Firewall
diagnostics.

The new command is:

```bash
memory-firewall hermes report --out <dir> [--hermes-home HOME] [--state-dir DIR] [--limit N] [--write-sample] [--open] [--json]
```

It writes:

- `report.json`
- `index.html`
- `redacted-share.json`

## Public Behavior

- Generates a local report from existing Hermes observation summaries.
- Includes setup status, observation counts, level/risk/detector counts, recent
  redacted observation rows, and next steps.
- Supports `--write-sample` for first-run validation without waiting for a real
  agent memory write.
- Adds `memory-firewall schema hermes-report`.
- Version moves to `0.1.0.dev16`.
- Schema/integration version moves to `mf-16`.

## Privacy Boundary

- Report rows use local observation handles such as `observation-row-1`.
- Raw candidate memory text and proposed memory text are not included in report
  JSON, HTML, or redacted share export.
- The local report may include local paths because it is for the user's machine.
- The redacted share export replaces the diagnostics path with
  `redacted-local-path`.

## Non-Goals

- No provider replacement.
- No enforcement.
- No Mem0/Honcho/GBrain write suppression.
- No trusted-context injection.
- No raw trace export.
- No hosted dashboard, telemetry service, auth, billing, or server process.
- No release tag, PyPI publish, or external launch execution.

## Review Focus

- Does `hermes report` preserve the observe-only boundary?
- Does the report avoid raw/proposed memory content in all generated files?
- Does the redacted share export remove local filesystem paths?
- Does the command give useful next steps for missing setup, no observations,
  and high-risk observations?
- Do version/schema/docs/tests move consistently to MF-16?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/cli.py src/memory_firewall/schema.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py
uv run --python 3.12 --extra dev pytest -q
UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema hermes-report
uv run --python 3.12 --extra dev memory-firewall hermes report --out /tmp/memory-firewall-mf16-report --write-sample --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf16-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf16-dist/*
```

The `hermes report --write-sample` smoke is expected to return exit code `1`
when the synthetic sample creates a high-risk observation; the pass condition is
that the report bundle is written, the JSON is schema-shaped, and raw candidate
memory text is not present in generated artifacts.
