# Memory Firewall

Contract and CLI shell for local-first integrity checks on persistent agent
memory.

Memory Firewall starts from one simple failure mode:

> A prompt injection can end while its effect survives inside memory.

Most memory systems focus on extraction, storage, consolidation, and retrieval.
Memory Firewall is a small public tool surface for asking a narrower question:

> What exactly has my agent remembered, and why am I letting it trust that?

## Status

This repository is in MF-01: product shell and contract freeze.

Implemented now:

- typed canonical `MemoryEvent` and `MemoryFinding` models;
- machine-readable event/finding schemas;
- risk taxonomy and claim budget;
- CLI commands for `doctor`, `schema`, `risks`, and `claims`;
- CI, package metadata, and review packet.

Not implemented yet:

- memory scanning;
- detector execution;
- quarantine;
- HTML reports;
- framework adapters;
- enforce mode.

## Install For Development

```bash
uv run --python 3.12 --extra dev memory-firewall doctor --json
uv run --python 3.12 --extra dev memory-firewall schema bundle
uv run --python 3.12 --extra dev memory-firewall risks
uv run --python 3.12 --extra dev memory-firewall claims
```

## Product Boundary

Memory Firewall is not a universal security boundary. It does not determine
objective truth, secure an entire agent, stop every poisoning attack, or
automatically approve important memories.

The broader public launch target is an installable local artifact for scanning
and explaining integrity risks in persistent agent memory. MF-01 does not ship
that scanner. It freezes the contract, CLI, and claim boundary that later
scanner and adapter work must obey. Enforcement claims are allowed only where
Memory Firewall controls the relevant read/write chokepoint.

## Relationship To Agent Memory Contracts

`agent-memory-contracts` is the public semantic trust kernel. Memory Firewall is
the public contract and CLI shell for the scanner/reference guardrail we are
building on top of that direction. Private production adapters and orchestration
may live elsewhere; this repo must stand on its own as a useful open-source
artifact.
