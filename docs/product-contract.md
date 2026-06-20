# Memory Firewall Product Contract

MF-04 adds deterministic local detectors over supplied `MemoryEvent` JSON while
keeping scanner, adapter, quarantine, trusted-read, and enforcement claims out
of scope.

## Category Line

`A prompt injection can end while its effect survives inside memory.`

## User-Facing Question

`What exactly has my agent remembered, and why am I letting it trust that?`

## Public Stack

```text
agent-memory-contracts
    Public semantic trust kernel and conformance layer

memory-firewall
    Public contract, detector pack, conformance probe, and CLI shell for the
    future inspection/demo/reference guardrail

private orchestration layer
    Production adapters, orchestration, and enterprise control plane, not in
    this public repository
```

## MF-04 Allows

- package installation;
- `memory-firewall doctor`;
- machine-readable event and finding schemas;
- machine-readable detector pack and detector result schemas;
- deterministic event IDs for adapter-emitted `MemoryEvent` payloads;
- deterministic finding IDs for `MemoryFinding` payloads;
- structured evidence spans anchored to event text fields;
- deterministic policy recommendation defaults;
- deterministic heuristic detectors over one supplied `MemoryEvent` JSON
  document;
- policy recommendations for detector findings;
- machine-readable adapter capability reports;
- a conformance probe over the built-in fake adapter;
- frozen risk taxonomy;
- explicit allowed claims and non-claims.

## MF-04 Does Not Allow

- real memory scanning claims;
- claims that detectors prove objective truth, adversarial intent, or universal
  poisoning detection;
- quarantine claims;
- trusted-read claims;
- real framework adapter claims;
- enforcement claims;
- claims that Memory Firewall determines objective truth;
- claims that Memory Firewall secures an entire agent.

## Operation Vocabulary

The `operation` enum is contract vocabulary for adapter/event producers:

- `create`
- `update`
- `upsert`
- `delete`
- `import`

These values describe the proposed memory operation. They do not mean MF-04 can
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

Memory Firewall also defines deterministic event IDs. The id is derived from the
canonical event material excluding `event_id`, using a stable JSON encoding and
SHA-256 digest prefix. This gives adapters a reproducible id surface without
claiming semantic truth or deduplication across incompatible memory systems.

## Finding And Evidence Surface

The canonical `MemoryFinding` contains:

- `finding_id`
- `event_id`
- `risk_category`
- `severity`
- `confidence`
- `evidence_span`
- `detector_name`
- `detector_version`
- `explanation`
- `recommended_disposition`
- `limitations`

Memory Firewall defines deterministic finding IDs. The id is derived from canonical
finding material excluding `finding_id`.

The structured `EvidenceSpan` contains:

- `source_field`
- `start`
- `end`
- `quote`

Evidence spans can be validated against a supplied `MemoryEvent`; the quoted
text must exactly match the referenced event field and character offsets.
This proves local anchoring only. It does not prove the quoted text is true.

## Policy Surface

Memory Firewall defines deterministic policy recommendation defaults:

- severity order: `informational`, `suspicious`, `high_impact`;
- disposition order: `pass`, `warn`, `review`, `quarantine`;
- suspicious findings above the review threshold escalate to `review`;
- high-impact findings above the quarantine threshold escalate to advisory
  `quarantine`;
- a finding's own recommended disposition can only make the result stricter.

Policy output is an inspectable recommendation. It is not automatic approval,
quarantine storage, or enforcement.

## Detector Surface

MF-04 ships a built-in deterministic detector pack. The pack runs only over a
supplied `MemoryEvent`; it does not scan a store, watch a directory, connect to
a framework, call an LLM, use the network, or inspect files beyond an explicitly
provided event JSON path.

The built-in detector pack currently includes heuristics for:

- provenance gaps;
- instruction-like persistence patterns;
- authority, ownership, approval, access, or payment changes;
- stale or temporal state;
- scope and privacy-sensitive content;
- secret-like or credential-like content;
- repeated sentence-like content.

Detector findings must include explicit limitations and anchored evidence spans.
They are review signals. They do not prove that text is false, malicious,
poisoned, or safe.

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

`quarantine` is only an advisory disposition value in MF-04. This sprint does
not implement quarantine storage or enforcement.

Use `poisoned` only for attack demos or confirmed adversarial cases. Normal
findings should distinguish severity from disposition according to the actual
proof available.
