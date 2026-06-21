# MF-18 Version-Aware Hermes Diagnostics

MF-18 follows real Hermes dogfood where old MF-16/MF-17 rows remained in the
same local diagnostics file as new calibrated rows. The product gap is
interpretability: a local alpha user should be able to tell whether a HIGH-RISK
row was produced by the current adapter behavior or by older dogfood history.

## Scope

- Move package/schema/Hermes versions to MF-18 / `0.1.0.dev18`.
- Preserve the raw row's recorded `integration_version` in redacted Hermes
  observation summaries as `recorded_integration_version`.
- Add current-version and legacy/unknown-version counters to Hermes status,
  checkup, report JSON, CLI text, and local HTML report summaries.
- Add a Version column to the local Hermes report table.
- Update README, product contract, and claim budget for the new reporting
  surface.

## Non-Goals

- No migration, deletion, rewrite, or reclassification of historical diagnostics.
- No enforcement.
- No provider replacement.
- No trusted ledger write or reducer decision.
- No hosted dashboard, telemetry, release tag, or PyPI publish.
- No broad real memory-store scanning claim beyond the observe-only Hermes hook
  alpha.

## Review Questions

- Do redacted outputs expose the recorded adapter version without leaking raw
  candidate memory text, event IDs, source IDs, or local paths in the redacted
  share artifact?
- Do status/checkup/report JSON schemas match runtime output exactly?
- Are legacy or missing row versions counted as non-current rather than
  accidentally credited to the current adapter?
- Do historical rows keep their stored scan levels instead of being recalibrated
  by the MF-18 reader?
- Do docs avoid implying migration, approval, trust promotion, provider
  replacement, or enforcement?

## Expected Gates

- Focused tests: `tests/test_hermes.py`, `tests/test_cli.py`,
  `tests/test_schema_and_taxonomy.py`.
- Full pytest.
- Mypy for supported Python versions.
- Schema/doctor/claims smokes.
- Build/twine and installed-wheel smoke.
- Actual Hermes checkup/report smoke after installing the local branch into the
  Hermes environment.
