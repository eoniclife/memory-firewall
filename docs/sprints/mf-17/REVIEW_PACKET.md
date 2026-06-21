# MF-17 Signal Calibration From Real Hermes Dogfood

MF-17 follows a live Hermes dogfood run where the installed `memory-firewall`
plugin captured a real built-in `memory` tool write, but summarized the
harmless marker as `high_risk` solely because the source authority was
untrusted. That made the adapter look noisier than the actual risk.

## Scope

- Downgrade provenance-only untrusted memory writes to WARN/review signals.
- Keep contradictions, blocked low-authority contradictions, and detector
  REVIEW/QUARANTINE findings HIGH-RISK.
- Keep Hermes diagnostics redacted and observe-only.
- Move package/schema/Hermes versions to MF-17 / `0.1.0.dev17`.
- Update README/product contract to describe the calibrated signal boundary.

## Non-Goals

- No enforcement.
- No provider replacement.
- No trusted ledger write or reducer decision.
- No hosted dashboard, telemetry, release tag, or PyPI publish.
- No broad real memory-store scanning claim beyond the observe-only Hermes hook
  alpha.

## Review Questions

- Does the scan-level change preserve high-risk behavior for contradictions and
  hazardous content?
- Do provenance-only events remain visible and reviewable as WARN rather than
  disappearing as PASS?
- Do Hermes status/observations/report counts reflect the calibrated level
  without leaking raw memory content?
- Do docs avoid implying approval, trust promotion, or enforcement?

## Local Dogfood Evidence

- Before MF-17, real Hermes session `20260621_055537_eb3585` wrote:
  `MF-17 dogfood marker 2026-06-21: Memory Firewall adapter observed a real
  Hermes memory write path.`
- The plugin recorded observation row 4 from `post_tool_call` / `memory`.
- The row had only `provenance-gap-v1`, no instruction detector, no secret
  detector, and no contradiction.
- MF-17 calibrates that shape to WARN while preserving HIGH-RISK for the
  existing synthetic injection samples.

## Expected Gates

- Focused tests: `tests/test_scan.py`, `tests/test_hermes.py`,
  `tests/test_cli.py`, `tests/test_schema_and_taxonomy.py`.
- Full pytest.
- Mypy for supported Python versions.
- Schema/doctor/claims smokes.
- Build/twine and installed-wheel smoke.
- Actual Hermes dogfood report after reinstalling the local branch into the
  Hermes environment.
