# MF-28 Review Packet: Link-Ready Public Artifact

## Scope

Base main: `dc6a0357bb8f191e7666443a7e1cdd26506bd0a9`

MF-28 makes the public repository link-ready for a memory trust-boundary post:

- README starts with a first-run path and explains the expected nonzero lineage
  diagnostic;
- `memory-firewall diagnostic sqlite-write-through --workspace <dir> --json`
  provides an installable local SQLite write-through diagnostic;
- `examples/authority_boundary_lineage.json` provides a synthetic
  authority-boundary evidence packet;
- the product contract and claim budget include MF-27 lineage diagnostics and
  explicitly preserve public/private claim boundaries;
- package metadata moves to `0.1.0.dev28`.

## Why

The repo already had useful primitives, but the public landing surface still
looked like MF-23 and the strongest evidence surfaces were not front-and-center.
MF-28 turns the repo into a runnable proof artifact without publishing private
validation packets or naming a live provider as vulnerable.

## Diagnostic

Run the installable local write-through diagnostic:

```bash
uv run --python 3.12 --extra dev memory-firewall diagnostic sqlite-write-through --workspace ./mf-sqlite-diagnostic --json
```

Expected result:

- exit code `0`;
- `native_rows` is `3`;
- observations are `pass`, `warn`, and `high_risk`;
- `attention_required` is `true`;
- `raw_content_included`, `writer_result_included`, and
  `production_enforcement` are all `false`;
- `report/report.json`, `report/index.html`, and `report/redacted-share.json`
  exist under the workspace.

Run the lineage boundary packet:

```bash
uv run --python 3.12 --extra dev memory-firewall lineage report examples/authority_boundary_lineage.json --json
```

Expected result:

- exit code `1`;
- issue code `downstream_candidate_not_escalated`;
- one downstream-used candidate;
- zero downstream-used candidates escalated;
- candidate-level scan status with WARN disposition.

This is a synthetic fixture. It proves the diagnostic shape, not exploitability
of a named live provider.

## Non-Goals

- No private validation packet publication.
- No live Mem0, GBrain, Hermes, Honcho, LangChain, Letta, Zep, vector-store, or
  hosted-provider vulnerability claim.
- No new provider adapter.
- No release tag, PyPI publish, hosted dashboard, telemetry service, trusted
  ledger, or production enforcement.

## Reviewer Focus

Check especially:

- README first-run commands are correct and claim-safe;
- SQLite diagnostic preserves native writes while emitting redacted observations
  and does not claim prevention or provider support;
- the authority-boundary fixture is synthetic but structurally meaningful;
- claim budget and product contract do not overclaim lineage evidence;
- `doctor --json` reports the new package version;
- the stale PR #25 surface is not copied forward without MF-27 lineage.

## Local Gates

- `git diff --check`: pass.
- `uv run --python 3.12 --extra dev pytest tests/test_diagnostic.py tests/test_public_examples.py tests/test_examples.py tests/test_cli.py -q`: pass.
- `uv run --python 3.12 --extra dev pytest -q`: pass.
- `uv run --python 3.12 --extra dev mypy src/memory_firewall tests`: pass.
- CLI smoke: `doctor --json`, `diagnostic sqlite-write-through --json`,
  non-empty-directory and existing-file unsafe workspace preservation,
  no bad-path traceback or absolute path leak, `demo poison --json`, and
  lineage report expected exit `1` all passed.
- Package smoke: `uv build`, `twine check`, clean venv wheel install,
  installed `doctor --json`, installed diagnostic, installed existing-file
  unsafe workspace preservation without traceback or path leak, and installed
  lineage report all passed.
- Claim/private leak scan: no private paths, secrets, WP packet names, ChatGPT
  URLs, or live-provider exploit claims found. Non-claim caveats matched expected
  terms such as provider vulnerability proof and production enforcement proof.
