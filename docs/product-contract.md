# Memory Firewall Product Contract

MF-01 freezes the product surface before detectors and adapters are added.

## Category Line

`A prompt injection can end while its effect survives inside memory.`

## User-Facing Question

`What exactly has my agent remembered, and why am I letting it trust that?`

## Public Stack

```text
agent-memory-contracts
    Public semantic trust kernel and conformance layer

memory-firewall
    Public contract and CLI shell for the future scanner/demo/reference guardrail

governed-memory
    Private product orchestration, production adapters, enterprise layer
```

## MF-01 Allows

- package installation;
- `memory-firewall doctor`;
- machine-readable event and finding schemas;
- frozen risk taxonomy;
- explicit allowed claims and non-claims.

## MF-01 Does Not Allow

- real memory scanning claims;
- detector claims;
- quarantine claims;
- adapter claims;
- enforcement claims;
- claims that Memory Firewall determines objective truth;
- claims that Memory Firewall secures an entire agent.

## Operation Vocabulary

The MF-01 `operation` enum is contract vocabulary for adapter/event producers:

- `create`
- `update`
- `upsert`
- `delete`
- `import`

These values describe the proposed memory operation. They do not mean MF-01 can
execute, block, or enforce that operation.

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

`quarantine` is only an advisory disposition value in MF-01. This sprint does
not implement quarantine storage or enforcement.

Use `poisoned` only for attack demos or confirmed adversarial cases. Normal
findings should distinguish severity from disposition according to the actual
proof available.
