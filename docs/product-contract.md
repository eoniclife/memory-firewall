# Memory Firewall Product Contract

MF-09 adds a custom SQLite reference proxy with explicit observe, overlay, and
enforce behavior over a controlled local substrate while keeping real
memory-store scanning, framework adapters, trusted ledger writes, and production
enforcement claims out of scope.

## Category Line

`A prompt injection can end while its effect survives inside memory.`

## User-Facing Question

`What exactly has my agent remembered, and why am I letting it trust that?`

## Public Stack

```text
agent-memory-contracts
    Public semantic trust kernel and conformance layer

memory-firewall
    Public contract, detector pack, AMC candidate/evidence preview, normalized
    event-stream scan/watch, local review queue, override receipts, trusted-read
    preview, poisoning demo, reference proxy, conformance probe, and CLI shell
    for the future inspection/demo/reference guardrail

private orchestration layer
    Production adapters, orchestration, and enterprise control plane, not in
    this public repository
```

## MF-09 Allows

- package installation;
- `memory-firewall doctor`;
- machine-readable event and finding schemas;
- machine-readable detector pack and detector result schemas;
- deterministic event IDs for adapter-emitted `MemoryEvent` payloads;
- deterministic finding IDs for `MemoryFinding` payloads;
- structured evidence spans anchored to event fields;
- deterministic policy recommendation defaults;
- deterministic heuristic detectors over one supplied `MemoryEvent` JSON
  document;
- policy recommendations for detector findings;
- deterministic local state assertions derived from supplied `MemoryEvent`
  payloads;
- declared source-authority assessment;
- contradiction checks against caller-supplied `MemoryStateAssertion` fixtures;
- supersession candidates when a higher-authority update conflicts with an
  older assertion;
- AMC `SourceRecord`, `EvidenceSpan`, and `CandidateClaim` preview records that
  validate against `agent-memory-contracts==1.3.0`;
- redaction of sensitive candidate text in the AMC preview when detector output
  indicates secret-like or privacy-sensitive content;
- finite scan over caller-supplied normalized `MemoryEvent` JSONL files;
- stdin watch over caller-supplied normalized `MemoryEvent` JSONL streams;
- scan-local rolling assertion context for contradiction analysis;
- fixed-cap scan-local context containing only clean, review-eligible
  assertions;
- structured scan issues for invalid JSONL lines without echoing raw line
  content;
- deterministic scan/watch exit codes:
  - `0`: completed with no invalid lines and no high-risk events;
  - `1`: completed with at least one high-risk event;
  - `2`: one or more invalid input lines were found;
  - `130`: watch was interrupted before clean EOF;
- a local file-backed review queue for high-risk scan events;
- deterministic review item ids and item hashes;
- explicit allow/reject decisions with required reasons;
- deterministic override receipts for local review decisions;
- idempotent repeated decisions when the same receipt material is supplied;
- a local trusted-read preview over allowed, receipted review items;
- exclusion of rejected review items from trusted-read preview items;
- a deterministic local poisoning demo over a toy last-write-wins memory store;
- `memory-firewall demo poison --json`;
- a machine-readable `demo-result` schema;
- a custom SQLite reference proxy controlled by this package;
- `memory-firewall proxy reference --mode observe|overlay|enforce --json`;
- observe mode that preserves native writes while reporting scan/review
  outcomes;
- overlay mode that preserves native writes while exposing a separate governed
  context preview for clean pass records;
- enforce mode that suppresses high-risk writes only inside the reference
  SQLite store;
- a machine-readable `reference-proxy-result` schema;
- machine-readable adapter capability reports;
- a conformance probe over the built-in fake adapter;
- frozen risk taxonomy;
- explicit allowed claims and non-claims.

## MF-09 Does Not Allow

- real memory-store scanning claims;
- claims that detectors prove objective truth, adversarial intent, or universal
  poisoning detection;
- claims that state analysis proves truth or authorizes trusted memory;
- claims that scan-local assertion context is a trusted ledger or reducer
  decision;
- automatic approval by an LLM;
- trusted ledger writes or reducer decisions;
- claims that local review queue storage is enforced quarantine;
- claims that trusted-read preview is a trusted ledger, reducer decision, or
  production read broker;
- claims that the poisoning demo is a benchmark, real adapter, real memory
  framework, or production enforcement proof;
- claims that the reference proxy is Mem0, Hermes, GBrain, LangChain, Letta,
  Zep, vector-store, or production framework support;
- claims that reference enforce mode secures native memory outside the
  controlled SQLite substrate;
- real framework adapter claims;
- production enforcement claims;
- claims that Memory Firewall determines objective truth;
- claims that Memory Firewall secures an entire agent.

## Operation Vocabulary

The `operation` enum is contract vocabulary for adapter/event producers:

- `create`
- `update`
- `upsert`
- `delete`
- `import`

These values describe the proposed memory operation. They do not mean Memory
Firewall can execute, block, import from a framework, or enforce that operation.

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
For secret-like findings, the span intentionally anchors only a non-secret
label or prefix rather than reproducing the complete matched secret. This proves
local anchoring only. It does not prove the quoted text is true.

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

MF-04 ships a built-in deterministic detector pack. The pack runs only over
supplied `MemoryEvent` payloads; it does not scan a store, watch a directory,
connect to a framework, call an LLM, use the network, or inspect files beyond
explicitly provided event JSON/JSONL paths.

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

## State Analysis Surface

MF-05 adds `memory-firewall analyze --event <path|-> --json`.

The command runs the deterministic detector pack, derives one local
`MemoryStateAssertion`, assesses declared source authority, checks for
contradictions against optional caller-supplied `MemoryStateAssertion` records,
and emits an AMC candidate/evidence preview.

The state-analysis result contains:

- `analysis_id`
- `analysis_version`
- `event_id`
- `assertion`
- `authority_assessment`
- `contradictions`
- `supersession_candidate_ids`
- `trusted_state_action`
- `reason_codes`
- `limitations`
- `finding_ids`
- `amc_mapping`

`trusted_state_action` is deliberately conservative:

- `candidate_only`
- `requires_reducer_review`
- `blocked_low_authority_contradiction`

A low-authority contradiction cannot silently become trusted state in MF-05:
it is emitted as `blocked_low_authority_contradiction` and the AMC candidate
preview remains `needs_review`. A higher-authority conflicting update can only
create a supersession candidate. It still requires reducer review and does not
write trusted state.

The AMC mapping is a preview surface for later reducer workflows. It does not
call `MemoryGate.promote`, write ledger records, create trusted snapshots, or
approve memory.

## Scan And Watch Surface

MF-06 added:

- `memory-firewall scan <events.jsonl>`;
- `memory-firewall scan <events.jsonl> --json`;
- `memory-firewall scan <events.jsonl> --json --summary-only`;
- `memory-firewall watch --stdin`;
- `memory-firewall watch --stdin --json`.

Both commands expect normalized `MemoryEvent` JSON objects, one per line. They
do not connect to a live framework or memory store. The scan/watch layer
composes existing detector, policy, and state-analysis surfaces. It does not
create a separate judgment path.

`HIGH-RISK` includes detector dispositions that require review/quarantine and
state-analysis outcomes that require reducer review, including higher-authority
contradictions. Such events are not clean pass events.

Finite scans keep only bounded scan-local assertion context needed for
contradiction analysis. Only clean, review-eligible events can seed that
context; low-authority or high-risk candidates are not fed back as future
state. That context is not trusted state, is not written to disk, and is not a
reducer decision. JSON output includes event records unless `--summary-only` is
used. Invalid input lines emit structured issues with generic error messages and
no raw line echo.

Watch mode remains stdin-only. It emits one terminal or JSONL result per
input line and handles `KeyboardInterrupt` without a traceback.

## Review Queue And Trusted-Read Preview Surface

MF-07 adds:

- `memory-firewall review enqueue <events.jsonl> --queue <queue.json>`;
- `memory-firewall review list --queue <queue.json>`;
- `memory-firewall review allow --queue <queue.json> --item-id <id> --reason <text>`;
- `memory-firewall review reject --queue <queue.json> --item-id <id> --reason <text>`;
- `memory-firewall review trusted-read-preview --queue <queue.json>`.

`review enqueue` runs the scan path and persists only high-risk scan
events as pending local review items. Clean pass events are skipped. Invalid
input lines remain scan issues; they are not converted into trusted-read preview
items.

Review items store candidate assertion material, state-analysis action,
finding summaries, ids, counts, and hashes. They do not store raw invalid JSONL
lines or full detector evidence quotes. Allow/reject requires a non-empty
reason and writes a deterministic local receipt. Supplying the same decision
material again is idempotent; conflicting later decisions are rejected.

The trusted-read preview includes only allowed, receipted review items. It is a
local preview of assertions the operator has explicitly allowed. It does not
write trusted state, call `MemoryGate.promote`, suppress native writes, connect
to an adapter, or prove that the assertion is objectively true. Rejected and
pending items are excluded from preview items.

## Poisoning Demo Surface

MF-08 adds:

- `memory-firewall demo poison`;
- `memory-firewall demo poison --json`;
- `memory-firewall schema demo-result`.

The demo is intentionally small and local. It creates two normalized
`MemoryEvent` records:

- a signed source-of-record memory saying the project codename is `Helio`;
- an untrusted later write trying to remember `Mirage` for the same durable
  fact.

The toy naive store is last-write-wins, so after both writes it answers
`Mirage`. Memory Firewall then runs the same events through scan and review:
the signed record passes, the untrusted conflicting write becomes high-risk,
the pending trusted-read preview stays empty, a reject decision keeps the forged
memory out of preview, and a separate explicit override path appears only with
a local receipt.

This demo makes the persistent-memory failure mode inspectable. It does not
wrap Mem0, Letta, Zep, Hermes, GBrain, LangChain, SQLite, a vector database, or
any real memory substrate. It is not a benchmark and does not prove that Memory
Firewall detects every poisoning attempt.

## Reference Proxy Surface

MF-09 adds:

- `memory-firewall proxy reference --mode observe`;
- `memory-firewall proxy reference --mode overlay`;
- `memory-firewall proxy reference --mode enforce`;
- `memory-firewall proxy reference --mode enforce --json`;
- `memory-firewall schema reference-proxy-result`.

The reference proxy uses a local SQLite store owned by this package. It runs the
same two-record project-codename fixture used by the poisoning demo through the
existing scan, review queue, and trusted-read preview path.

Mode behavior is deliberately explicit:

- `observe`: native writes are preserved; the native read returns the forged
  value `Mirage`; no governed context channel is provided.
- `overlay`: native writes are preserved; the native read returns `Mirage`; a
  separate governed context preview returns the clean signed-record value
  `Helio`.
- `enforce`: the high-risk write is suppressed inside the reference store; the
  native read and governed context preview both return `Helio`.

The governed context preview is not a trusted ledger write, reducer decision,
or production read broker. It is a local reference-channel preview for this
controlled substrate. Reference enforce mode does not imply that Memory
Firewall can suppress writes in Mem0, Letta, Zep, Hermes, GBrain, LangChain,
SQLite databases it does not control, vector stores, or any other real memory
framework.

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

`quarantine` is only an advisory disposition value. MF-09 implements local
review-queue storage and a reference-store enforce demo, not production
framework quarantine or adapter suppression.

Use `poisoned` only for attack demos or confirmed adversarial cases. Normal
findings should distinguish severity from disposition according to the actual
proof available.
