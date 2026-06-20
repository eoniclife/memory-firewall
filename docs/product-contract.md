# Memory Firewall Product Contract

MF-02 freezes the product surface before detectors and real framework adapters
are added.

## Category Line

`A prompt injection can end while its effect survives inside memory.`

## User-Facing Question

`What exactly has my agent remembered, and why am I letting it trust that?`

## Public Stack

```text
agent-memory-contracts
    Public semantic trust kernel and conformance layer

memory-firewall
    Public contract, conformance probe, and CLI shell for the future
    scanner/demo/reference guardrail

private orchestration layer
    Production adapters, orchestration, and enterprise control plane, not in
    this public repository
```

## MF-02 Allows

- package installation;
- `memory-firewall doctor`;
- machine-readable event and finding schemas;
- deterministic event IDs for adapter-emitted `MemoryEvent` payloads;
- machine-readable adapter capability reports;
- a conformance probe over the built-in fake adapter;
- frozen risk taxonomy;
- explicit allowed claims and non-claims.

## MF-02 Does Not Allow

- real memory scanning claims;
- detector claims;
- quarantine claims;
- real framework adapter claims;
- enforcement claims;
- claims that Memory Firewall determines objective truth;
- claims that Memory Firewall secures an entire agent.

## Operation Vocabulary

The MF-02 `operation` enum is contract vocabulary for adapter/event producers:

- `create`
- `update`
- `upsert`
- `delete`
- `import`

These values describe the proposed memory operation. They do not mean MF-02 can
execute, block, import from a framework, or enforce that operation.

## Canonical Event Surface

The canonical `MemoryEvent` contains:

- `event_id`
- `timestamp`
- `actor`
- `user_or_tenant_scope`
- `source_type`
- `source_id`
- `source_authority`
- `raw_or_redacted_content`
- `proposed_memory`
- `operation`
- `target_namespace`
- `metadata`

MF-02 also defines deterministic event IDs. The id is derived from the
canonical event material excluding `event_id`, using a stable JSON encoding and
SHA-256 digest prefix. This gives adapters a reproducible id surface without
claiming semantic truth or deduplication across incompatible memory systems.

## Adapter Capability Surface

The adapter capability report contains:

- `adapter_name`
- `adapter_version`
- `supported_capabilities`
- `unsupported_capabilities`
- `notes`
- `metadata`

Capabilities are disclosure vocabulary, not proof of enforcement. The built-in
demo adapter exists only to exercise the conformance contract. It does not wrap
Mem0, Letta, Zep, Hermes, GBrain, LangChain, a vector store, SQLite, or any
other real memory substrate.

## Risk Categories

- provenance gap;
- instruction injection;
- authority or identity change;
- contradiction;
- temporal or stale state;
- scope or privacy violation;
- procedural poisoning;
- anomalous persistence.

## Severity And Disposition Vocabulary

Severity describes the level of concern:

- `informational`
- `suspicious`
- `high_impact`

Disposition describes the recommended handling:

- `pass`
- `warn`
- `review`
- `quarantine`

`quarantine` is only an advisory disposition value in MF-02. This sprint does
not implement quarantine storage or enforcement.

Use `poisoned` only for attack demos or confirmed adversarial cases. Normal
findings should distinguish severity from disposition according to the actual
proof available.
