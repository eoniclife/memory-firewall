# MF-26 Review Packet: First-Run Launch Readiness

## Scope

This sprint is a launch-readiness polish pass after personally running the
public first-run path as a user.

Changes are limited to:

- top-level package version alignment from `0.1.0.dev23` to `0.1.0.dev25`;
- README quickstart instructions for GitHub install / `uv tool run`;
- README status text that explains MF-24/MF-25 without implying new runtime
  schemas or enforcement;
- product-contract wording that marks MF-25 as the current public package
  surface and keeps the public claim budget bounded.

## User-Style Proof

Clean GitHub install from public main `ab51d66ff1e0f3643a20dac2d2bad9119e4984ee`
was tested before this patch:

```bash
uv venv --python 3.12 /tmp/memory-firewall-user-test/venv
uv pip install --python /tmp/memory-firewall-user-test/venv/bin/python \
  "git+https://github.com/eoniclife/memory-firewall.git@ab51d66ff1e0f3643a20dac2d2bad9119e4984ee"
memory-firewall doctor --json
memory-firewall demo poison --json
memory-firewall report demo --out /tmp/memory-firewall-user-test/out/demo-report --json
memory-firewall adapter observe-memory --content "..." --target profile --source-authority untrusted --json
memory-firewall adapter report --out /tmp/memory-firewall-user-test/out/adapter-report --json
python examples/generic_write_through_sqlite.py --workspace /tmp/memory-firewall-user-test/out/sqlite-example
```

Observed result:

- GitHub install succeeded with `agent-memory-contracts==1.3.0`.
- `doctor` returned `ok: true`.
- `demo poison` showed naive memory poisoned (`Mirage`) while the
  source-of-record remained `Helio`.
- generic adapter observe/report returned exit code `1` for high-risk content,
  as expected.
- SQLite example preserved three native writes and produced one pass, one warn,
  and one high-risk observation.
- generated report/share directories did not contain the raw malicious text or
  fake writer token; private diagnostics did contain raw candidate text, as
  documented.

## Local Gates

Post-patch gates:

```bash
git diff --check
uv run --python 3.12 --extra dev pytest -q
uv run --python 3.12 --extra dev mypy
uv run --python 3.12 --extra dev python -m compileall -q src tests examples
uv build --out-dir /tmp/memory-firewall-mf25-launch-dist
uv run --python 3.12 --extra dev twine check /tmp/memory-firewall-mf25-launch-dist/*
```

All passed.

Clean installed-wheel smoke from the built artifact:

```bash
uv venv --python 3.12 /tmp/memory-firewall-mf25-launch-wheel-smoke/venv
uv pip install --python /tmp/memory-firewall-mf25-launch-wheel-smoke/venv/bin/python \
  /tmp/memory-firewall-mf25-launch-dist/memory_firewall-0.1.0.dev25-py3-none-any.whl
memory-firewall --version
memory-firewall doctor --json
memory-firewall demo poison --json
memory-firewall report demo --out /tmp/memory-firewall-mf25-launch-wheel-smoke/out/demo-report --json
memory-firewall adapter observe-memory --content "..." --target profile --source-authority untrusted --json
memory-firewall adapter report --out /tmp/memory-firewall-mf25-launch-wheel-smoke/out/adapter-report --json
```

Observed result:

- installed package version: `0.1.0.dev25`;
- `doctor` returned `ok: true`;
- poison demo retained the expected naive-vs-source-of-record outcome;
- adapter high-risk commands returned exit code `1`, as expected;
- report leak scan found no raw malicious candidate text in generated
  report/share directories.

## Acceptance Criteria

- No new runtime behavior.
- No new schema version claims.
- No release, tag, PyPI publish, hosted service, telemetry, UI, provider
  replacement, trusted-ledger, broad memory-store scanning, or production
  enforcement claim.
- README lets a user try the public demo before reading the development command
  matrix.
- Product contract remains aligned with public claim boundaries.

## Residual Risk

The first-run path is still engineer-facing and JSON-heavy. It proves the point,
but a launch post or demo video should extract the visceral story from the JSON
instead of expecting users to discover it unaided.
