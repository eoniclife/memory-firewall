# MF-19 Fresh Current-Version Hermes Dogfood Runbook

MF-19 is a documentation and dogfood pass over the MF-18 runtime/schema surface.
It does not change package version, schema version, code behavior, enforcement,
provider wiring, or release status.

## Scope

- Add a README runbook for producing a fresh current-version Hermes observation
  after install or upgrade.
- Explain how to interpret `current_version_observations`,
  `legacy_version_observations`, and `recorded_integration_version`.
- Clarify that older HIGH-RISK rows can keep Hermes diagnostics commands at exit
  code `1` even when the newest current-version row is WARN.
- Update the product contract to label MF-19 as documentation-only.

## Non-Goals

- No runtime behavior change.
- No package or schema version bump.
- No migration, deletion, rewrite, or reclassification of historical diagnostics.
- No enforcement.
- No provider replacement.
- No trusted ledger write or reducer decision.
- No hosted dashboard, telemetry, release tag, or PyPI publish.

## Actual Hermes Dogfood Evidence

After MF-18 merged, actual `/Users/a/.hermes` was installed editable at
`0.1.0.dev18` and the generated shim was refreshed. A fresh Hermes oneshot used
the built-in `memory` tool on harmless test text. Memory Firewall recorded a new
row:

- row: `observation-row-6`;
- `recorded_integration_version`: `mf-18`;
- level: `warn`;
- disposition: `warn`;
- detector: `provenance-gap-v1`;
- target: `hermes:memory:memory`.

The actual status after this dogfood run reported:

- `total_observations`: 6;
- `current_version_observations`: 1;
- `legacy_version_observations`: 5;
- `warn_observations`: 2;
- `high_risk_observations`: 4.

The actual report still exited `1` because high-risk legacy rows remain in the
local diagnostics history. Its latest row was the MF-18 current-version WARN row,
and `redacted-share.json` omitted the raw dogfood marker, raw/proposed memory
fields, old injection sample text, `sk-test-secret`, and local filesystem paths.

## Review Questions

- Does the README make the first real Hermes dogfood path reproducible?
- Does it warn users that the test prompt is written into Hermes memory?
- Does it avoid implying enforcement, provider replacement, migration, or
  current-version reclassification of historical rows?
- Does it explain why a command/report can still return exit code `1` when older
  high-risk rows remain?
- Does the product contract correctly describe MF-19 as documentation-only over
  the MF-18 runtime/schema surface?

## Expected Gates

- Documentation review.
- `uv run --python 3.12 --extra dev pytest tests/test_cli.py tests/test_hermes.py tests/test_schema_and_taxonomy.py -q`
- `git diff --check`
- `uv run --python 3.12 --extra dev memory-firewall doctor --json`
- `uv run --python 3.12 --extra dev memory-firewall claims --json`
- PR CI before merge.
