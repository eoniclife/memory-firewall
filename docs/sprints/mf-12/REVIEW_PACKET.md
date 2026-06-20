# MF-12 Hermes Install Shim

## Scope

MF-12 makes the MF-11 Hermes hook alpha actually enableable in the user's
current Hermes installation.

It adds:

- `memory-firewall hermes install-plugin`;
- `install_hermes_plugin_shim(...)`;
- a generated `~/.hermes/plugins/memory-firewall/plugin.yaml`;
- a generated `~/.hermes/plugins/memory-firewall/__init__.py` shim that
  imports `memory_firewall.hermes_plugin.register`;
- README, product contract, claim budget, version, schema, and tests.

## Trigger

After MF-11 merged, local dogfood found:

- installing `memory-firewall` into `~/.hermes/hermes-agent/venv` made
  Python entry-point discovery work;
- Hermes runtime `PluginManager` saw `memory-firewall` as a
  `hermes_agent.plugins` entry point;
- `memory-firewall hermes status --json` worked inside the Hermes venv;
- `hermes plugins list` and `hermes plugins enable memory-firewall` did not see
  the entry-point plugin because Hermes v0.16.0's CLI helper discovers bundled
  and user directory plugins only;
- `hermes plugins enable memory-firewall` failed with:

```text
Plugin 'memory-firewall' is not installed or bundled.
```

## Public Behavior

The installer writes a small user-plugin directory that Hermes' current CLI can
discover:

```text
~/.hermes/plugins/memory-firewall/
  plugin.yaml
  __init__.py
```

The generated `__init__.py` delegates to the installed package:

```python
from memory_firewall.hermes_plugin import register
```

The runtime hook logic remains in the installed package.

## Commands

```bash
python -m pip install -e .
memory-firewall hermes install-plugin
hermes plugins enable memory-firewall
memory-firewall hermes status --json
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

- Does the installer produce a Hermes directory plugin compatible with Hermes
  v0.16.0 `plugins list/enable` discovery?
- Is the generated shim minimal and clearly delegated to the installed package?
- Does `--force` avoid silently overwriting mismatched existing files?
- Do docs avoid implying provider wrapping or enforcement?
- Does the package version/schema advance cleanly to MF-12?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q
uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py
uv run --python 3.12 --extra dev pytest -q
UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests
UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall hermes install-plugin --hermes-home <temp-dir> --json
git diff --check
uv build --out-dir /tmp/memory-firewall-mf12-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf12-dist/*
```

Dogfood gate must additionally verify Hermes' own CLI can list and enable the
generated shim in the user's Hermes installation.

## Local Gate Results

- focused MF-12/Hermes/schema tests:
  `uv run --python 3.12 --extra dev pytest tests/test_hermes.py tests/test_cli.py tests/test_schema_and_taxonomy.py -q`
  - `56` passed.
- focused type checks:
  `uv run --python 3.12 --extra dev mypy src/memory_firewall/hermes.py src/memory_firewall/cli.py src/memory_firewall/__init__.py tests/test_hermes.py tests/test_cli.py`
  - `Success: no issues found in 5 source files`.
- full test suite:
  `uv run --python 3.12 --extra dev pytest -q`
  - passed for the collected `162` tests.
- full type checks:
  - `UV_PROJECT_ENVIRONMENT=.venv-310-mypy uv run --python 3.10 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-311-mypy uv run --python 3.11 --extra dev mypy src tests`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-mypy uv run --python 3.12 --extra dev mypy src tests`
  - all reported `Success: no issues found in 36 source files`.
- bytecode and whitespace:
  - `uv run --python 3.12 --extra dev python -m compileall -q src tests`
  - `git diff --check`
- CLI/schema/Hermes smokes:
  - `memory-firewall doctor --json`
  - `memory-firewall schema bundle`
  - `memory-firewall hermes install-plugin --hermes-home <temp-dir> --json`
  - `memory-firewall hermes status --state-dir <empty-temp-dir> --json`
- package build and metadata:
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv build --out-dir /tmp/memory-firewall-mf12-dist`
  - `UV_PROJECT_ENVIRONMENT=.venv-312-build uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf12-dist/*`
  - sdist and wheel passed.
- installed-wheel smoke:
  - created Python `3.12.11` venv with `uv venv`;
  - installed `memory_firewall-0.1.0.dev12-py3-none-any.whl`;
  - `memory-firewall --version` returned `0.1.0.dev12`;
  - `memory-firewall hermes install-plugin --hermes-home <temp-dir> --json`
    wrote `plugin.yaml` and `__init__.py`;
  - `importlib.metadata.entry_points(group="hermes_agent.plugins")` found and
    loaded `memory_firewall.hermes_plugin`;
  - `uv pip check` passed.

## Dogfood Results

Local Hermes target:

- `Hermes Agent v0.16.0 (2026.6.5)`;
- executable: `~/.local/bin/hermes`;
- runtime Python: `~/.hermes/hermes-agent/venv/bin/python`;
- config backup created before enable:
  `~/.hermes/config.yaml.bak-memory-firewall-mf12-enable-*`.

Observed after installing the editable package into Hermes' venv:

- `memory-firewall --version` returned `0.1.0.dev12`;
- `memory-firewall hermes install-plugin --json` created
  `~/.hermes/plugins/memory-firewall/plugin.yaml` and `__init__.py`;
- `hermes plugins list --plain --no-bundled` showed
  `memory-firewall` as a user plugin;
- `hermes plugins enable memory-firewall` succeeded;
- `plugins.enabled` in Hermes config contains `memory-firewall`;
- Hermes runtime `PluginManager` loaded `memory-firewall` with hooks:
  `pre_tool_call`, `post_tool_call`, and `post_llm_call`;
- invoking Hermes' `post_tool_call` hook for a built-in `memory` write produced
  one high-risk observation;
- `memory-firewall hermes status --state-dir /tmp/memory-firewall-hermes-dogfood --json`
  reported:
  - `integration_version`: `mf-12`;
  - `total_observations`: `1`;
  - `high_risk_observations`: `1`;
  - `observe_only`: `true`;
  - `production_enforcement`: `false`;
- diagnostics permissions were verified:
  - state dir: `0700`;
  - `events.jsonl`: `0600`;
  - `observations.jsonl`: `0600`.

## Residual Risks

- The shim relies on Hermes' existing user-plugin directory discovery.
- A future Hermes release may fix entry-point enable/list discovery, making the
  shim unnecessary but still harmless.
- The hook is still observe-only. Enforcement and provider wrapping remain
  later sprints.
