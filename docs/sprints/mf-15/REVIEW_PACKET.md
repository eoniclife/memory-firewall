# MF-15 Hermes Config Hint Dogfood Fix

## Scope

MF-15 fixes one dogfood bug in the MF-14 Hermes checkup.

Hermes' own `plugins enable memory-firewall` command can serialize
`plugins.enabled` as:

```yaml
plugins:
  enabled:
  - memory-firewall
```

MF-14's narrow local parser only accepted list items indented deeper than
`enabled:`, so actual Hermes reported the plugin enabled while
`memory-firewall hermes checkup` still returned `needs_setup`.

## Public Behavior

- `memory-firewall hermes checkup --json` recognizes the valid Hermes CLI
  `plugins.enabled` list style.
- Version moves to `0.1.0.dev15`.
- Schema/integration version moves to `mf-15`.
- Product boundary remains observe-only.

## Non-Goals

- No full YAML dependency.
- No Hermes core patch.
- No provider replacement.
- No enforcement.
- No Mem0/Honcho/GBrain write suppression.
- No release tag, PyPI publish, or external launch execution.

## Review Focus

- Does the parser still reject commented/stale substring matches?
- Does it accept both indented and Hermes-emitted `plugins.enabled` list styles?
- Does checkup still avoid claiming runtime plugin load or enforcement?
- Do version/schema/docs/tests move consistently to MF-15?

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
uv run --python 3.12 --extra dev memory-firewall schema hermes-checkup
git diff --check
uv build --out-dir /tmp/memory-firewall-mf15-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf15-dist/*
```
