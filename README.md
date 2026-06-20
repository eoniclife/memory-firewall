# Memory Firewall

Contract and CLI shell for local-first integrity checks on persistent agent
memory.

Memory Firewall starts from one simple failure mode:

> A prompt injection can end while its effect survives inside memory.

Most memory systems focus on extraction, storage, consolidation, and retrieval.
Memory Firewall is a small public tool surface for asking a narrower question:

> What exactly has my agent remembered, and why am I letting it trust that?

## Status

This repository is in MF-03: deterministic finding and policy model.

Implemented now:

- typed canonical `MemoryEvent` and `MemoryFinding` models;
- deterministic `MemoryEvent` IDs derived from canonical event material;
- deterministic `MemoryFinding` IDs derived from canonical finding material;
- structured evidence spans for finding receipts;
- deterministic policy recommendation defaults;
- adapter capability report model and schema;
- a built-in fake adapter conformance probe;
- machine-readable event/finding schemas;
- risk taxonomy and claim budget;
- CLI commands for `doctor`, `schema`, `risks`, `claims`, `policy`, and
  `conformance`;
- CI, package metadata, and review packet.

Not implemented yet:

- memory scanning;
- detector execution;
- quarantine;
- trusted read paths;
- HTML reports;
- framework adapters;
- enforce mode.

## Install For Development

```bash
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall schema adapter
uv run --python 3.12 --extra dev memory-firewall schema policy
uv run --python 3.12 --extra dev memory-firewall risks
uv run --python 3.12 --extra dev memory-firewall claims
uv run --python 3.12 --extra dev memory-firewall policy --json
uv run --python 3.12 --extra dev memory-firewall conformance demo --json
```

## Product Boundary

Memory Firewall is not a universal security boundary. It does not determine
objective truth, secure an entire agent, stop every poisoning attack, or
automatically approve important memories.

The broader public launch target is an installable local artifact for scanning
and explaining integrity risks in persistent agent memory. MF-03 does not ship
that scanner. It freezes event identity, finding identity, evidence spans,
policy recommendation vocabulary, adapter capability, conformance, CLI, and
claim boundaries that later scanner and adapter work must obey.
Enforcement claims are allowed only where Memory Firewall controls the relevant
read/write chokepoint.

## Relationship To Agent Memory Contracts

`agent-memory-contracts` is the public semantic trust kernel. Memory Firewall is
the public contract and CLI shell for the scanner/reference guardrail we are
building on top of that direction. Private production adapters and orchestration
may live elsewhere; this repo must stand on its own as a useful open-source
artifact.
