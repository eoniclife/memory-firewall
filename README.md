# Memory Firewall

Local-first contracts and deterministic integrity checks for persistent agent
memory.

Memory Firewall starts from one simple failure mode:

> A prompt injection can end while its effect survives inside memory.

Most memory systems focus on extraction, storage, consolidation, and retrieval.
Memory Firewall is a small public tool surface for asking a narrower question:

> What exactly has my agent remembered, and why am I letting it trust that?

## Status

This repository is in MF-11: a first observe-only Hermes hook alpha over the
existing Memory Firewall scan/detector/report surfaces.

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
- local Hermes diagnostics JSONL and `memory-firewall hermes status`;
- adapter capability report model and schema;
- a built-in fake adapter conformance probe;
- machine-readable event/finding/detector/state-analysis/scan/review/demo/proxy/report/Hermes
  status schemas;
- risk taxonomy and claim budget;
- CLI commands for `doctor`, `schema`, `risks`, `claims`, `policy`, `detect`,
  `analyze`, `scan`, `watch`, `review`, `demo`, `proxy`, `report`, `hermes`, and
  `conformance`;
- CI, package metadata, and review packet.

Not implemented yet:

- broad real memory-store scanning;
- real framework quarantine or adapter write suppression;
- trusted ledger writes;
- hosted HTML reports;
- framework adapters beyond the Hermes observe-only hook alpha;
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
uv run --python 3.12 --extra dev memory-firewall schema hermes-status
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
uv run --python 3.12 --extra dev memory-firewall hermes status --json
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
```

## Hermes Hook Alpha

The MF-11 Hermes integration is observe-only. Install the package into the same
Python environment that runs Hermes, enable the `memory-firewall` plugin in
Hermes, then start a fresh Hermes session.

```bash
python -m pip install -e .
hermes plugins enable memory-firewall
memory-firewall hermes status --json
```

By default the plugin records only high-signal memory write tool attempts.
Diagnostics are local JSONL files under `~/.hermes/memory-firewall/`, unless
`MEMORY_FIREWALL_HERMES_DIR` points somewhere else. Set
`MEMORY_FIREWALL_HERMES_SCAN_TURNS=1` only if you want noisy turn-level
observations for implicit memory-provider writes.

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
diagnostics. `memory-firewall hermes status --json` summarizes those local
observations. Turn-level scanning for implicit memory providers is opt-in via
`MEMORY_FIREWALL_HERMES_SCAN_TURNS=1`. MF-11 does not replace the active Hermes
memory provider, suppress Mem0/Honcho/GBrain writes, inject trusted context,
write a trusted ledger, or provide production enforcement.

## Relationship To Agent Memory Contracts

`agent-memory-contracts` is the public semantic trust kernel. Memory Firewall is
the public contract and CLI shell for the inspection/reference guardrail we are
building on top of that direction. Private production adapters and orchestration
may live elsewhere; this repo must stand on its own as a useful open-source
artifact.
