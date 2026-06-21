# Memory Firewall Product Contract

MF-20 adds an explicit current-version-only Hermes diagnostics lens over the
first observe-only Hermes hook alpha, Hermes user-plugin shim installer,
redacted Hermes observations readout, local Hermes checkup/report, calibrated
signal levels from real Hermes dogfood, version-aware diagnostics, and existing
scan, detector, review, proxy, and report surfaces while keeping broad real
memory-store scanning, provider replacement, trusted ledger writes, hosted
dashboards, and production enforcement claims out of scope.

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
    preview, poisoning demo, reference proxy, local static report, redacted
    share export, Hermes observe-only hook alpha, Hermes user-plugin shim
    installer, version-aware redacted Hermes observations readout,
    current-version-only diagnostics lens, local Hermes checkup, local Hermes
    diagnostics report, conformance probe, and CLI shell for the future
    inspection/demo/reference guardrail

private orchestration layer
    Production adapters, orchestration, and enterprise control plane, not in
    this public repository
```

## MF-20 Allows

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
- provenance-only untrusted memory writes to surface as WARN/review signals
  rather than HIGH-RISK alerts;
- state contradictions, blocked low-authority contradictions, and detector
  REVIEW/QUARANTINE findings to remain HIGH-RISK;
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
- a local static integrity report over the demo/proxy surfaces;
- `memory-firewall report demo --out <dir> --json`;
- report files `report.json`, `index.html`, and `redacted-share.json`;
- redacted share export that omits raw content, state-object answer values,
  event IDs, source IDs, review item IDs, and receipt IDs by default;
- machine-readable `report-result` and `redacted-report-export` schemas;
- a Hermes plugin entry point named `memory-firewall`;
- `memory-firewall hermes install-plugin`;
- observe-only Hermes hook registration for `pre_tool_call`, `post_tool_call`,
  and `post_llm_call`;
- normalization of high-signal Hermes memory write attempts into `MemoryEvent`
  records;
- local detector/policy scan over those Hermes-derived `MemoryEvent` records;
- local Hermes diagnostics JSONL for normalized events and observations, created
  or tightened with user-only local file permissions;
- `memory-firewall hermes status --json`;
- machine-readable `hermes-status` schema;
- `memory-firewall hermes observations --json`;
- redacted newest-first Hermes observation summaries over local diagnostics;
- recorded adapter-version labels on redacted Hermes observation summaries;
- explicit `--current-version-only` filtering for Hermes observations and
  reports;
- all-history totals and level counts plus `matching_*` counts in filtered
  Hermes diagnostics;
- machine-readable `hermes-observations` schema;
- `memory-firewall hermes checkup --json`;
- local Hermes setup checks over generated shim files, `plugins.enabled`
  config-file hints, diagnostics permissions, status counts, and recent
  redacted observations;
- current-vs-legacy or unknown adapter-version counts in Hermes status, checkup,
  and report summaries;
- explicit synthetic local observation writes for first-run readout validation;
- machine-readable `hermes-checkup` schema;
- `memory-firewall hermes report --out <dir> --json`;
- `memory-firewall hermes report --out <dir> --write-sample`;
- local Hermes report files `report.json`, `index.html`, and
  `redacted-share.json`;
- redacted Hermes report rows with local observation handles, setup status,
  detector/risk counts, and next steps;
- machine-readable `hermes-report` schema;
- opt-in turn-level scanning for implicit memory providers via
  `MEMORY_FIREWALL_HERMES_SCAN_TURNS=1`;
- local configuration of the Hermes diagnostics directory via
  `MEMORY_FIREWALL_HERMES_DIR`;
- a generated Hermes user-plugin shim under
  `~/.hermes/plugins/memory-firewall/` that delegates to the installed package;
- issue templates for adapter requests, false positives, detector suggestions,
  and redacted report feedback;
- machine-readable adapter capability reports;
- a conformance probe over the built-in fake adapter;
- frozen risk taxonomy;
- explicit allowed claims and non-claims.

## MF-20 Does Not Allow

- broad real memory-store scanning claims;
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
- claims that the Hermes hook alpha replaces a Hermes memory provider;
- claims that the Hermes hook alpha suppresses Mem0, Honcho, GBrain, built-in
  memory, MCP, or provider `sync_turn` writes;
- claims that Hermes observations are trusted ledger records, reducer
  decisions, or approved memories;
- claims that the Hermes observations CLI is a raw trace export or safe-to-share
  transcript export;
- claims that current-version-only Hermes views clear, delete, resolve,
  suppress, or reclassify legacy diagnostics;
- claims that Hermes checkup proves a live Hermes runtime has loaded the plugin;
- claims that Hermes checkup proves runtime enforcement, provider replacement,
  or write suppression;
- claims that the Hermes report is a raw trace export, approved-memory ledger,
  hosted dashboard, telemetry service, or enforcement audit;
- automatic trusted-context injection into Hermes prompts;
- claims that the local report is a hosted dashboard, telemetry service, auth
  system, billing system, or server process;
- raw-content sharing by default;
- claims that redacted report export is a raw trace export;
- release tag, PyPI publish, or external launch execution without a separate
  verified release gate;
- real framework adapter claims beyond the observe-only Hermes hook alpha;
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

`HIGH-RISK` includes detector dispositions that require review/quarantine,
state-analysis contradictions, and blocked low-authority contradictions. Under
MF-17 and later, provenance-only untrusted writes that require reducer review are
WARN signals rather than HIGH-RISK alerts. Such events are not clean pass events.

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

## Local Report Surface

MF-10 adds:

- `memory-firewall report demo --out <dir>`;
- `memory-firewall report demo --out <dir> --json`;
- `memory-firewall schema report-result`;
- `memory-firewall schema redacted-report-export`.

The demo report composes the deterministic poisoning demo and the reference
proxy observe/overlay/enforce outcomes. It writes:

- `report.json`: local structured report;
- `index.html`: self-contained local HTML report;
- `redacted-share.json`: default share-safe export.

The redacted export is the artifact users should paste into issues. It omits
raw content, proposed memory, event IDs, source IDs, state-object answer values,
review item IDs, and receipt IDs by default. It keeps aggregate counts, risk
categories, mode names, and capability boundaries so feedback is useful without
sharing raw traces.

The HTML report is local only. MF-10 does not start a hosted dashboard, server,
auth flow, billing flow, telemetry service, or production release workflow.
Actual tag or publish execution requires a separate verified gate.

## Hermes Hook Alpha Surface

MF-11 added:

- `memory_firewall.hermes_plugin:register`;
- `memory-firewall hermes status`;
- `memory-firewall hermes status --json`;
- `memory-firewall schema hermes-status`;
- a `hermes_agent.plugins` entry point named `memory-firewall`.

MF-12 adds:

- `memory-firewall hermes install-plugin`;
- a generated user-plugin shim at `~/.hermes/plugins/memory-firewall/`;
- `--hermes-home`, `--force`, and `--json` installer options.

MF-13 adds:

- `memory-firewall hermes observations`;
- `memory-firewall hermes observations --json`;
- `memory-firewall schema hermes-observations`;
- `--state-dir`, `--limit`, and `--json` observation readout options.

MF-14 adds:

- `memory-firewall hermes checkup`;
- `memory-firewall hermes checkup --json`;
- `memory-firewall hermes checkup --write-sample`;
- `memory-firewall schema hermes-checkup`;
- `--hermes-home`, `--state-dir`, `--limit`, and `--json` checkup options.

MF-15 fixes the checkup's local `plugins.enabled` hint parsing so it recognizes
the valid YAML list style emitted by Hermes' own `plugins enable` command.

MF-16 adds:

- `memory-firewall hermes report --out <dir>`;
- `memory-firewall hermes report --out <dir> --json`;
- `memory-firewall hermes report --out <dir> --write-sample`;
- `memory-firewall hermes report --out <dir> --open`;
- `memory-firewall schema hermes-report`;
- `--hermes-home`, `--state-dir`, `--limit`, `--write-sample`, `--open`, and
  `--json` report options.

MF-17 calibrates signal levels from real Hermes dogfood:

- provenance-only untrusted memory writes are WARN/review signals;
- contradictions and blocked low-authority contradictions remain HIGH-RISK;
- detector REVIEW/QUARANTINE findings remain HIGH-RISK;
- Hermes status, observations, and report summaries count those calibrated
  levels consistently.

MF-18 adds version-aware Hermes diagnostics:

- redacted observation summaries include the adapter version that recorded each
  row;
- Hermes status, checkup, and report summaries separate current-version rows
  from legacy or unknown-version rows;
- historical rows keep their original recorded scan levels, so MF-18 explains
  old dogfood history without silently recalibrating it.

MF-19 documents the fresh current-version dogfood path:

- install or upgrade the package inside the Python environment that runs Hermes;
- refresh the user-plugin shim with `memory-firewall hermes install-plugin
  --force`;
- enable the plugin with `hermes plugins enable memory-firewall`;
- start a fresh Hermes oneshot or session that uses the built-in `memory` tool
  on harmless test text;
- verify that `current_version_observations` increased and that the newest
  redacted observation's `recorded_integration_version` matches the top-level
  `integration_version`;
- generate `redacted-share.json` as the safe-to-share report artifact.

MF-20 adds explicit current-version-only Hermes diagnostics:

- `memory-firewall hermes observations --current-version-only`;
- `memory-firewall hermes report --current-version-only --out <dir>`;
- filtered outputs set `observation_scope: current_version`;
- filtered outputs retain all-history totals and level counts, and expose
  `matching_*` counts for the selected scope;
- current-version-only report exit status is based on setup readiness and
  whether rows exist in the selected scope plus matching high-risk rows, not
  legacy high-risk rows outside the selected scope;
- historical diagnostics are not deleted, rewritten, migrated, reclassified, or
  hidden from unfiltered commands.

The Hermes hook alpha is deliberately observe-only. It can be enabled by Hermes
as a standalone plugin and can run alongside the active Hermes memory provider.
It does not set `memory.provider`, wrap a provider, replace Mem0/Honcho, or
mutate GBrain.

The plugin observes high-signal memory-write attempts from Hermes tool hooks,
including the built-in `memory` tool, provider write tools such as
`mem0_conclude` and `honcho_conclude`, and obvious GBrain write tools. It
normalizes those attempts into `MemoryEvent` records, runs local Memory
Firewall scan/detector policy, and writes local JSONL diagnostics:

- `events.jsonl`;
- `observations.jsonl`.

The diagnostics directory is created or tightened to user-only permissions, and
both diagnostics files are created or tightened to owner-read/write
permissions. These files may contain raw candidate memory text, so the status
CLI summarizes counts and levels without printing raw event content.

Turn-level scanning for implicit provider writes is disabled by default because
it can be noisy. It is enabled only when
`MEMORY_FIREWALL_HERMES_SCAN_TURNS=1` is set.

MF-11 does not claim to see provider-internal `sync_turn` writes exactly, block
native memory writes, inject trusted read previews, or enforce quarantine. Those
belong to later provider-wrapper or policy-gate sprints.

The MF-12 installer is a Hermes CLI compatibility shim. It does not patch
Hermes, configure a Hermes memory provider, or move runtime logic into the
generated files. The generated `plugin.yaml` and `__init__.py` let current
Hermes CLI discovery list and enable the installed package's observe-only hook
module.

The MF-13 observations readout is redacted. It shows recent observation
metadata such as recorded time, hook/tool name, redacted target namespace, a
local row handle, level, disposition, finding count, contradiction count, risk
categories, and detector names. It does not print raw candidate memory text or
turn transcripts, does not expose the raw-derived MemoryEvent ID in the redacted
readout, and does not make the underlying local diagnostics safe to share
wholesale.

The MF-15 checkup readout is local setup evidence. It can say whether generated
shim files match this package, whether a local config file lists
`memory-firewall` under `plugins.enabled`, whether diagnostics paths have
private permissions, and whether redacted observations are readable. With
`--write-sample`, it writes one synthetic local observation to prove the readout
path. It does not prove a live Hermes runtime has loaded the plugin in a current
session.

The MF-16 Hermes report is a local redacted diagnostics report over the same
Hermes observations. It writes `report.json`, `index.html`, and
`redacted-share.json` into the chosen output directory. The local report can
show local paths, setup status, observation counts, redacted row handles,
detector/risk counts, and next steps. The redacted share export removes local
filesystem paths and does not include raw candidate memory text. The report is
not a raw trace export, approved-memory ledger, hosted dashboard, telemetry
service, provider replacement, or enforcement proof.

The MF-17 signal calibration does not approve provenance-only memory, promote it
to trusted state, or suppress review. It only prevents normal untrusted agent
memory writes from looking as urgent as injection, secret, contradiction, or
policy-quarantine events.

The MF-18 version readout does not migrate, rewrite, delete, or reclassify
historical diagnostics. It is a reporting aid for local alpha dogfood.

The MF-19 runbook does not add runtime behavior, schema fields, enforcement, or
provider replacement. It records how to reproduce the alpha path safely with
harmless test text.

The MF-20 current-version-only lens does not clear historical diagnostics or
prove that legacy high-risk observations are resolved. It is a scoped report
view for upgrade and first-run clarity.

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

`quarantine` is only an advisory disposition value. MF-11 implements local
review-queue storage, a reference-store enforce demo, local reports, and an
observe-only Hermes hook alpha, not production framework quarantine or adapter
suppression.

Use `poisoned` only for attack demos or confirmed adversarial cases. Normal
findings should distinguish severity from disposition according to the actual
proof available.
