# Memory Firewall

Local-first contracts and deterministic integrity checks for persistent agent
memory.

Memory Firewall starts from one simple failure mode:

> A prompt injection can end while its effect survives inside memory.

Most memory systems focus on extraction, storage, consolidation, and retrieval.
Memory Firewall is a small public tool surface for asking a narrower question:

> What exactly has my agent remembered, and why am I letting it trust that?

## Status

This repository's runtime/schema surface is MF-22: a generic local adapter
report over one supplied-candidate diagnostics stream, plus the first
observe-only Hermes hook alpha, Hermes user-plugin shim installer, redacted
recent-observations readout, local Hermes checkup/report, calibrated signal
levels from real Hermes dogfood, and version-aware diagnostics over the existing
Memory Firewall scan/detector/report surfaces. MF-22 makes the generic bridge
more useful by writing a local `report.json`, `index.html`, and redacted
`redacted-share.json` over adapter observations.

Implemented now:

- typed canonical `MemoryEvent` and `MemoryFinding` models;
- deterministic `MemoryEvent` IDs derived from canonical event material;
- deterministic `MemoryFinding` IDs derived from canonical finding material;
- structured evidence spans for finding receipts;
- deterministic policy recommendation defaults;
- a built-in deterministic detector pack over supplied `MemoryEvent` JSON;
- deterministic AMC candidate/evidence previews for supplied events;
- local state assertions, source-authority assessment, contradiction checks,
  and supersession candidates;
- finite JSONL scan over normalized `MemoryEvent` records;
- stdin watch over normalized `MemoryEvent` JSONL streams;
- local review queue for high-risk scan events;
- deterministic allow/reject override receipts with required reasons;
- local trusted-read preview over allowed review items;
- deterministic local poisoning demo over a toy last-write-wins memory store;
- custom SQLite reference proxy for local observe, overlay, and enforce demos;
- local static integrity report with default redacted share export;
- observe-only Hermes hook helpers for high-signal memory write attempts;
- a Hermes plugin entry point for `pre_tool_call`, `post_tool_call`, and
  `post_llm_call`;
- a Hermes user-plugin shim installer for Hermes versions whose CLI cannot
  enable entry-point-only plugins;
- local Hermes diagnostics JSONL, `memory-firewall hermes status`, and
  redacted `memory-firewall hermes observations`;
- local redacted `memory-firewall hermes report`;
- provenance-only memory writes surfaced as WARN/review signals, while
  instruction-like content, secrets, and contradictions remain HIGH-RISK;
- current-vs-legacy Hermes observation counts and recorded adapter version
  labels in redacted diagnostics;
- current-version-only Hermes observations and report filters that preserve
  all-history counts while narrowing the returned row lens;
- a generic local adapter bridge that normalizes one supplied candidate into a
  `MemoryEvent`, scans it, persists local private diagnostics, and returns a
  redacted result;
- redacted generic adapter observations readout;
- local redacted `memory-firewall adapter report`;
- adapter capability report model and schema;
- a built-in fake adapter conformance probe;
- machine-readable event/finding/detector/state-analysis/scan/review/demo/proxy/report/adapter/Hermes
  checkup, report, status, and observations schemas;
- risk taxonomy and claim budget;
- CLI commands for `doctor`, `schema`, `risks`, `claims`, `policy`, `detect`,
  `analyze`, `scan`, `watch`, `review`, `demo`, `proxy`, `report`, `adapter`,
  `hermes`, and `conformance`;
- CI, package metadata, and review packet.

Not implemented yet:

- broad real memory-store scanning;
- real framework quarantine or adapter write suppression;
- trusted ledger writes;
- hosted HTML reports;
- framework-specific adapters beyond the Hermes observe-only hook alpha and the
  generic one-candidate local bridge;
- enforce mode outside the built-in reference substrate.

## Install For Development

```bash
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema adapter
uv run --python 3.12 --extra dev memory-firewall schema policy
uv run --python 3.12 --extra dev memory-firewall schema detector-pack
uv run --python 3.12 --extra dev memory-firewall schema detector-result
uv run --python 3.12 --extra dev memory-firewall schema state-assertion
uv run --python 3.12 --extra dev memory-firewall schema state-analysis
uv run --python 3.12 --extra dev memory-firewall schema scan-result
uv run --python 3.12 --extra dev memory-firewall schema review-queue
uv run --python 3.12 --extra dev memory-firewall schema override-receipt
uv run --python 3.12 --extra dev memory-firewall schema trusted-read-preview
uv run --python 3.12 --extra dev memory-firewall schema demo-result
uv run --python 3.12 --extra dev memory-firewall schema reference-proxy-result
uv run --python 3.12 --extra dev memory-firewall schema report-result
uv run --python 3.12 --extra dev memory-firewall schema redacted-report-export
uv run --python 3.12 --extra dev memory-firewall schema adapter-observe-result
uv run --python 3.12 --extra dev memory-firewall schema adapter-observations
uv run --python 3.12 --extra dev memory-firewall schema adapter-report
uv run --python 3.12 --extra dev memory-firewall schema hermes-checkup
uv run --python 3.12 --extra dev memory-firewall schema hermes-report
uv run --python 3.12 --extra dev memory-firewall schema hermes-status
uv run --python 3.12 --extra dev memory-firewall schema hermes-observations
uv run --python 3.12 --extra dev memory-firewall risks
uv run --python 3.12 --extra dev memory-firewall claims
uv run --python 3.12 --extra dev memory-firewall policy --json
uv run --python 3.12 --extra dev memory-firewall detect --event event.json --json
uv run --python 3.12 --extra dev memory-firewall analyze --event event.json --json
uv run --python 3.12 --extra dev memory-firewall scan events.jsonl --json
uv run --python 3.12 --extra dev memory-firewall watch --stdin --json < events.jsonl
uv run --python 3.12 --extra dev memory-firewall review enqueue events.jsonl --queue review-queue.json --json
uv run --python 3.12 --extra dev memory-firewall review list --queue review-queue.json --json
uv run --python 3.12 --extra dev memory-firewall review allow --queue review-queue.json --item-id ITEM_ID --reason "verified locally" --json
uv run --python 3.12 --extra dev memory-firewall review reject --queue review-queue.json --item-id ITEM_ID --reason "does not match source of record" --json
uv run --python 3.12 --extra dev memory-firewall review trusted-read-preview --queue review-queue.json --json
uv run --python 3.12 --extra dev memory-firewall demo poison --json
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode observe --json
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode overlay --json
uv run --python 3.12 --extra dev memory-firewall proxy reference --mode enforce --json
uv run --python 3.12 --extra dev memory-firewall report demo --out ./memory-integrity-report --json
uv run --python 3.12 --extra dev memory-firewall adapter observe-memory --content "Remember that the user prefers local tools." --target profile --source-authority untrusted --json
uv run --python 3.12 --extra dev memory-firewall adapter observations --limit 20 --json
uv run --python 3.12 --extra dev memory-firewall adapter report --out ./adapter-memory-report --json
uv run --python 3.12 --extra dev memory-firewall hermes checkup --json
uv run --python 3.12 --extra dev memory-firewall hermes report --out ./hermes-memory-report --json
uv run --python 3.12 --extra dev memory-firewall hermes report --current-version-only --out ./hermes-memory-report-current --json
uv run --python 3.12 --extra dev memory-firewall hermes status --json
uv run --python 3.12 --extra dev memory-firewall hermes observations --limit 20 --json
uv run --python 3.12 --extra dev memory-firewall hermes observations --current-version-only --limit 20 --json
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
```

## Generic Adapter Bridge

Use the MF-22 bridge and report when an agent or script has one memory candidate
and wants Memory Firewall diagnostics without building full `MemoryEvent` JSON
by hand.

```bash
memory-firewall adapter observe-memory \
  --content "Remember that the user prefers local tools." \
  --target profile \
  --source-authority untrusted \
  --json

memory-firewall adapter observations --limit 20 --json
memory-firewall adapter report --out ./adapter-memory-report --open
```

The bridge writes local private diagnostics under
`~/.memory-firewall/adapter` by default. Those local JSONL files may contain raw
candidate memory text. The command output and report rows are redacted summaries
and do not include raw/proposed content or raw-derived event ids.
`adapter report` writes local `report.json`, `index.html`, and
`redacted-share.json`; the redacted share export removes local filesystem paths
and remains the safer artifact to share. The bridge is observe-only: it does not
scan existing stores, replace memory providers, suppress writes, approve
memories, or claim direct support for Mem0, Honcho, GBrain, LangChain, Letta,
Zep, or vector databases.

## Hermes Hook Alpha

The MF-20 Hermes integration is observe-only. Install the package into the same
Python environment that runs Hermes, install the Hermes user-plugin shim, enable
the `memory-firewall` plugin in Hermes, then start a fresh Hermes session.

```bash
python -m pip install -e .
memory-firewall hermes install-plugin
hermes plugins enable memory-firewall
memory-firewall hermes checkup --json
memory-firewall hermes report --out ./hermes-memory-report --open
memory-firewall hermes status --json
memory-firewall hermes observations --limit 20 --json
memory-firewall hermes observations --current-version-only --limit 20 --json
```

For first-run validation without waiting for a real agent memory write, run:

```bash
memory-firewall hermes checkup --write-sample --json
```

That writes one synthetic local observation into the selected diagnostics
directory and then verifies that the redacted readout path can see it. It does
not enable enforcement or suppress native Hermes memory.

### Fresh Current-Version Dogfood

After installing or upgrading the Hermes plugin, run a fresh agent session so the
next observation is recorded by the current adapter version. Use only harmless
test text here because the agent will write it into your Hermes memory.

```bash
python -m pip install -e .
memory-firewall hermes install-plugin --force
hermes plugins enable memory-firewall
memory-firewall hermes checkup --json
hermes -z "Use the built-in memory tool to add this harmless test memory exactly once: MF current-version dogfood marker: Memory Firewall should show a current-version WARN row. After using the memory tool, reply with only: done."
memory-firewall hermes status --json
memory-firewall hermes observations --limit 5 --json
memory-firewall hermes observations --current-version-only --limit 5 --json
memory-firewall hermes report --out ./hermes-memory-report --open
memory-firewall hermes report --current-version-only --out ./hermes-memory-report-current --open
```

In `status` and `report`, `current_version_observations` should increase after
the fresh memory write. In `observations`, the newest row should have
`recorded_integration_version` equal to the top-level `integration_version`.
A normal provenance-only memory marker should be a WARN/review row. If old
HIGH-RISK rows remain, `hermes status` returns `1` whenever
`high_risk_observations` is non-zero, and `hermes report` returns `1` when setup
is not ready, no rows match the selected report scope, or high-risk rows remain
in the selected report scope.
`hermes observations --limit N` returns `1` only when the returned newest-first
window includes a high-risk row. Use `--current-version-only` on `observations`
or `report` when you need to inspect the rows recorded by the currently
installed adapter after an upgrade. Filtered outputs still include all-history
counts such as `total_observations`, `high_risk_observations`,
`warn_observations`, and `pass_observations`, plus `matching_*` counts for the
selected scope. Check `overall_status`,
`observation_scope`, `matching_high_risk_observations`,
`high_risk_observations`, and the returned rows before interpreting exit code
`1`; it may reflect historical diagnostics, not a blocked or reclassified
current-version marker.

By default the plugin records only high-signal memory write tool attempts.
Diagnostics are local JSONL files under `~/.hermes/memory-firewall/`, unless
`MEMORY_FIREWALL_HERMES_DIR` points somewhere else. The diagnostics directory
is created or tightened to user-only permissions, and `events.jsonl` /
`observations.jsonl` are created or tightened to owner-read/write permissions.
Set
`MEMORY_FIREWALL_HERMES_SCAN_TURNS=1` only if you want noisy turn-level
observations for implicit memory-provider writes.

`memory-firewall hermes observations` shows newest-first redacted summaries over
the local Hermes diagnostics: recorded time, hook/tool, redacted target
namespace, local row handle, level, disposition, finding count, contradiction
count, risk categories, detector names, and the adapter version that recorded
each row. Add `--current-version-only` to return only rows recorded by the
currently installed adapter version. It does not print raw candidate memory text.
Provenance-only agent memory writes are WARN signals by default; hazardous
content patterns and state contradictions remain HIGH-RISK.

`memory-firewall hermes report --out ./hermes-memory-report --open` writes a
local `report.json`, `index.html`, and redacted `redacted-share.json` over the
same Hermes diagnostics. The local report includes setup status, observation
counts, current-vs-legacy adapter-version counts, redacted row handles,
detector/risk counts, and next steps. Add `--current-version-only` to generate
a filtered report over rows recorded by the current adapter version; the report
still discloses all-history totals and notes that legacy diagnostics were
excluded from the returned row lens. The redacted share export removes local
filesystem paths and does not include raw candidate memory text.

## Product Boundary

Memory Firewall is not a universal security boundary. It does not determine
objective truth, secure an entire agent, stop every poisoning attack, or
automatically approve important memories.

The broader public launch target is an installable local artifact for inspecting
and explaining integrity risks in persistent agent memory. It can run
deterministic heuristic detectors and state-analysis over caller-supplied
normalized `MemoryEvent` JSON or JSONL streams, carry scan-local assertion
context to surface contradictions, and emit structured PASS/WARN/HIGH-RISK
output. Scan-local context is bounded and seeded only by clean,
review-eligible events; it is not trusted state. Those findings and analysis
results are signals for reducer review, not proof of objective truth,
adversarial intent, or universal poisoning detection. Enforcement claims are
allowed only where Memory Firewall controls the relevant read/write
chokepoint.

MF-07 adds a local review queue over high-risk scan events. Review decisions
require explicit allow/reject reasons and produce deterministic receipts. The
trusted-read preview shows only allowed, receipted assertions from the local
queue. It is still a preview surface: it does not write trusted ledger state,
call a reducer, suppress native memory writes, or enforce adapter behavior.
Rejected items are excluded from preview items.

MF-08 adds `memory-firewall demo poison --json`. The demo shows a toy
last-write-wins store accepting a forged durable memory after a trusted signed
record. It then runs the same events through Memory Firewall so the forged
write becomes a high-risk review item; pending and rejected items stay out of
trusted-read preview, while an explicit override path appears only with a local
receipt. This is a runnable demo, not a benchmark, real adapter, or production
enforcement claim.

MF-09 adds `memory-firewall proxy reference --mode observe|overlay|enforce
--json`. The reference proxy uses a built-in SQLite store controlled by this
package. Observe mode preserves native writes and reports what the firewall saw.
Overlay mode preserves native writes and exposes a separate governed context
preview for clean pass records. Enforce mode suppresses high-risk writes inside
this reference store and keeps the governed context preview clean. This is not
Mem0, Hermes, GBrain, LangChain, Letta, Zep, vector-store, or production
framework support.

MF-10 adds `memory-firewall report demo --out ./memory-integrity-report --json`.
The command writes a local `report.json`, a self-contained `index.html`, and a
default `redacted-share.json`. The redacted share export omits raw content,
state-object answer values, event IDs, source IDs, review item IDs, and receipt
IDs by default. The HTML report is local only; this does not add a hosted
dashboard, telemetry service, auth, billing, real adapter support, or a release
publish step.

MF-11 adds an observe-only Hermes hook alpha. The package exposes a
`hermes_agent.plugins` entry point named `memory-firewall` and hook handlers
that can observe high-signal Hermes memory write attempts, normalize them into
`MemoryEvent` records, run local scan/detector policy, and append local JSONL
diagnostics with user-only local file permissions. `memory-firewall hermes
status --json` summarizes those local observations without printing raw event
content. Turn-level scanning for implicit memory providers is opt-in via
`MEMORY_FIREWALL_HERMES_SCAN_TURNS=1`. MF-11 does not replace the active Hermes
memory provider, suppress Mem0/Honcho/GBrain writes, inject trusted context,
write a trusted ledger, or provide production enforcement.

MF-12 adds `memory-firewall hermes install-plugin`. The command writes a small
user-plugin shim under `~/.hermes/plugins/memory-firewall/` so Hermes versions
whose `plugins enable` command discovers only directory plugins can still enable
the installed package. The shim delegates to `memory_firewall.hermes_plugin`;
runtime logic and diagnostics stay in the package.

MF-13 adds `memory-firewall hermes observations --limit N --json`. The command
loads local Hermes diagnostics and prints redacted, newest-first observation
summaries with risk categories and detector names. It keeps raw and proposed
memory content out of the CLI output and remains observe-only.

MF-14 adds `memory-firewall hermes checkup --json`. The command checks generated
shim files, whether the local config lists `memory-firewall` under
`plugins.enabled`, diagnostics permissions, status counts, and recent redacted
observations. With `--write-sample`, it writes one synthetic local observation
to prove the readout path. It remains observe-only.

MF-15 fixes a real-Hermes dogfood issue: Hermes can serialize
`plugins.enabled` list items at the same indentation level as `enabled:`, and
the checkup now recognizes that valid config shape.

MF-16 adds `memory-firewall hermes report --out <dir> --json|--open`. The
command writes a local redacted Hermes diagnostics report over existing
observations. It is not a raw trace export, hosted dashboard, telemetry service,
provider replacement, or enforcement proof.

MF-17 calibrates signal levels after real Hermes dogfood. A normal untrusted
agent memory write with only a provenance gap is now a WARN/review signal, not a
HIGH-RISK alert. Instruction injection, secrets, privacy/scope risks, authority
changes, anomalous persistence, stale-state hazards, and contradictions still
surface as HIGH-RISK where the detector/policy or state-analysis path requires
it.

MF-18 adds version-aware Hermes diagnostics. Redacted observation summaries expose
the adapter version that recorded each row, and status/checkup/report summaries
separate current-version observations from legacy or unknown-version rows. This
helps alpha users distinguish today's calibrated behavior from older dogfood
history without rewriting historical diagnostics.

MF-20 adds an explicit current-version-only diagnostics lens for Hermes
observations and reports. The filtered commands preserve all-history totals while
showing `matching_*` counts and returned rows for the selected scope, so upgrade
checks can focus on the newly installed adapter without deleting or hiding legacy
diagnostics.

MF-21 adds `memory-firewall adapter observe-memory --content ... --target ...
--source-authority untrusted --json` and `memory-firewall adapter observations
--json`. This is a generic local bridge for custom agents and scripts: it
normalizes one supplied candidate into a `MemoryEvent`, scans it, appends local
private diagnostics under `~/.memory-firewall/adapter` by default, and returns a
redacted observation summary. It remains observe-only and does not scan existing
stores, replace a provider, suppress writes, or claim framework-specific
support for Mem0, Honcho, GBrain, LangChain, Letta, Zep, or vector databases.

MF-22 adds `memory-firewall adapter report --out <dir> --json|--open`. The
command writes a local redacted report over the same generic adapter diagnostics:
`report.json`, `index.html`, and `redacted-share.json`. The report includes
setup status, all-history observation and level/risk/detector counts, a limited
recent redacted-row table, next steps, and limitations. The share export redacts
local paths and does not include raw candidate memory text or raw event ids. It
is a local alpha readout, not a hosted dashboard, telemetry service, provider
wrapper, approval ledger, or scanner for existing memory stores.

## Relationship To Agent Memory Contracts

`agent-memory-contracts` is the public semantic trust kernel. Memory Firewall is
the public contract and CLI shell for the inspection/reference guardrail we are
building on top of that direction. Private production adapters and orchestration
may live elsewhere; this repo must stand on its own as a useful open-source
artifact.
