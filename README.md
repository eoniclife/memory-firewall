# Memory Firewall

Local-first contracts and deterministic integrity checks for persistent agent
memory.

Memory Firewall starts from one simple failure mode:

> A prompt injection can end while its effect survives inside memory.

Most memory systems focus on extraction, storage, consolidation, and retrieval.
Memory Firewall is a small public tool surface for asking a narrower question:

> What exactly has my agent remembered, and why am I letting it trust that?

## Status

This repository is in MF-07: local review queue, override receipts, and
trusted-read preview over normalized scan results.

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
- adapter capability report model and schema;
- a built-in fake adapter conformance probe;
- machine-readable event/finding/detector/state-analysis/scan/review schemas;
- risk taxonomy and claim budget;
- CLI commands for `doctor`, `schema`, `risks`, `claims`, `policy`, `detect`,
  `analyze`, `scan`, `watch`, `review`, and `conformance`;
- CI, package metadata, and review packet.

Not implemented yet:

- real memory-store scanning;
- real framework quarantine or adapter write suppression;
- trusted ledger writes;
- HTML reports;
- framework adapters;
- enforce mode.

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
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
```

## Product Boundary

Memory Firewall is not a universal security boundary. It does not determine
objective truth, secure an entire agent, stop every poisoning attack, or
automatically approve important memories.

The broader public launch target is an installable local artifact for inspecting
and explaining integrity risks in persistent agent memory. MF-07 still does not
connect to real stores. It can run deterministic heuristic detectors and
state-analysis over caller-supplied normalized `MemoryEvent` JSON or JSONL
streams, carry scan-local assertion context to surface contradictions, and emit
structured PASS/WARN/HIGH-RISK output. Scan-local context is bounded and seeded
only by clean, review-eligible events; it is not trusted state. Those findings
and analysis results are signals for reducer review, not proof of objective
truth, adversarial intent, or universal poisoning detection. Enforcement claims
are allowed only where Memory Firewall controls the relevant read/write
chokepoint.

MF-07 adds a local review queue over high-risk scan events. Review decisions
require explicit allow/reject reasons and produce deterministic receipts. The
trusted-read preview shows only allowed, receipted assertions from the local
queue. It is still a preview surface: it does not write trusted ledger state,
call a reducer, suppress native memory writes, or enforce adapter behavior.
Rejected items are excluded from preview items.

## Relationship To Agent Memory Contracts

`agent-memory-contracts` is the public semantic trust kernel. Memory Firewall is
the public contract and CLI shell for the inspection/reference guardrail we are
building on top of that direction. Private production adapters and orchestration
may live elsewhere; this repo must stand on its own as a useful open-source
artifact.
