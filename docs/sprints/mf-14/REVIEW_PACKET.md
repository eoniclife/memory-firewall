# MF-14 Hermes Quickstart Checkup

## Scope

MF-14 makes the observe-only Hermes adapter easier to dogfood after install.

It adds:

- `memory-firewall hermes checkup`;
- `memory-firewall hermes checkup --json`;
- `memory-firewall hermes checkup --write-sample`;
- `memory-firewall schema hermes-checkup`;
- README, product contract, claim budget, version, schema, and tests.

## Trigger

MF-12 made the Hermes shim installable. MF-13 made local observations readable.
The remaining first-run gap is that a user still has to remember several
commands and manually infer whether Memory Firewall is installed, enabled, and
able to show useful diagnostics.

## Public Behavior

The new command reports:

- package and integration version;
- Hermes home, config path, plugin shim path, manifest path, and init path;
- whether generated shim files match this installed package;
- whether the local Hermes config lists `memory-firewall` under
  `plugins.enabled`;
- diagnostics directory and JSONL file permission modes;
- Hermes status counts;
- recent redacted observations;
- next-step commands when setup is incomplete.

When `--state-dir` is omitted, checkup uses the same Hermes home for the
default diagnostics path, while still honoring `MEMORY_FIREWALL_HERMES_DIR` as
an explicit diagnostics override.

With `--write-sample`, it writes one synthetic local high-risk observation into
the selected diagnostics directory and then reads it back through the redacted
observations surface.

## Commands

```bash
memory-firewall hermes checkup --json
memory-firewall hermes checkup --write-sample --json
memory-firewall schema hermes-checkup
```

## Non-Goals

- No Hermes core patch.
- No provider replacement.
- No Mem0/Honcho/GBrain write suppression.
- No trusted ledger writes.
- No trusted context injection.
- No hosted dashboard or telemetry.
- No production enforcement claim.
- No release tag, PyPI publish, or external launch execution.

## Review Focus

- Does checkup avoid printing raw/proposed memory content?
- Does `--write-sample` make first-run validation obvious without claiming
  runtime enforcement?
- Does the JSON schema match the CLI/model output?
- Are missing, installed, enabled, empty, and sample-written states
  distinguishable?
- Does `--hermes-home` keep shim/config and default diagnostics paths aligned?
- Do remediation next steps preserve the selected Hermes home and tell users
  how to refresh stale generated shim files?
- Do docs avoid implying that config text proves a live Hermes runtime has
  loaded the plugin?

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
uv run --python 3.12 --extra dev memory-firewall hermes checkup --state-dir <temp-dir> --hermes-home <temp-dir> --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf14-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf14-dist/*
```

Dogfood should additionally verify that an installed package can run
`hermes checkup --write-sample`, produce one redacted observation, and avoid
printing the synthetic raw instruction text.
