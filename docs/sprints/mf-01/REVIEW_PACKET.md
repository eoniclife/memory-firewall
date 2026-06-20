# MF-01 Product Shell And Contract Freeze

## Scope

This sprint creates the public `memory-firewall` repository shell and freezes
the first product contract.

Added:

- `pyproject.toml`
- `MANIFEST.in`
- `src/memory_firewall/*`
- `tests/*`
- `.github/workflows/ci.yml`
- `docs/product-contract.md`
- `docs/sprints/mf-01/REVIEW_PACKET.md`
- `uv.lock`

## Intent

MF-01 should make the repo installable, reviewable, and honest before any demo
or detector work starts. It defines the public language, canonical event shape,
finding shape, risk taxonomy, and CLI inspection commands.

## Non-Goals

- No scan command.
- No detector execution.
- No quarantine implementation.
- No HTML report.
- No framework adapter.
- No enforce mode.
- No hosted service.
- No private `governed-memory` code.
- No release/tag/publish.

## Claim Budget

Allowed:

- Memory Firewall defines a canonical event surface for persistent memory
  writes.
- Memory Firewall defines an explainable risk taxonomy for memory-integrity
  findings.
- Memory Firewall can be installed and queried locally for its MF-01 contract.

Not allowed:

- Memory Firewall scans real stores today.
- Memory Firewall stops memory poisoning today.
- Memory Firewall determines objective truth.
- Memory Firewall secures an entire agent.
- Memory Firewall enforces controls on unsupported frameworks.

## Review Focus

- Does the public language overclaim?
- Are the event and finding schemas stable enough for MF-02/MF-03?
- Is the CLI useful without implying detectors exist?
- Is `agent-memory-contracts>=1.3,<1.4` included without leaking private
  `governed-memory` assumptions?
- Are local and CI gates sufficient for a public package shell?

## Expected Gates

```bash
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.10 --extra dev python -m mypy --python-version 3.10 src/memory_firewall tests
uv run --python 3.11 --extra dev python -m mypy --python-version 3.11 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m mypy --python-version 3.12 src/memory_firewall tests
uv run --python 3.12 --extra dev python -m compileall -q src tests
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
git diff --check
uv run --python 3.12 --extra dev python -m build
uv run --python 3.12 --extra dev python -m twine check dist/*
```

## Local Gate Results

Passed on branch `codex/mf-01-product-shell` before draft PR creation:

- Python 3.12 focused tests: `8` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `memory-firewall doctor --json` passed with compatible
  `agent-memory-contracts` 1.3.x.
- `memory-firewall schema bundle` emitted the MF-01 schema bundle.
- `git diff --check` passed.
- `python -m build` produced sdist and wheel.
- `twine check dist/*` passed.
- Installed-wheel smoke passed in a fresh Python 3.12 venv, including
  `doctor --json` and schema-bundle validation.

Fix-pass after independent reviewer/MiniMax requested claim-boundary changes:

- Python 3.12 tests: `14` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `memory-firewall doctor --json` passed with compatible
  `agent-memory-contracts` 1.3.x.
- `memory-firewall schema bundle` emitted valid JSON.
- `git diff --check` passed.
- rebuilt sdist/wheel passed `twine check`.
- installed-wheel smoke passed with `pip check`, `doctor --json`, and schema
  bundle validation.

Final polish after MiniMax accepted with nits:

- Python 3.12 tests: `16` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `git diff --check` passed.

Schema/parser alignment fix after independent final re-review:

- Python 3.12 tests: `18` passed.
- mypy passed for Python `3.10`, `3.11`, and `3.12`.
- `compileall` passed for `src` and `tests`.
- `git diff --check` passed.
