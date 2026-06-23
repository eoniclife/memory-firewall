"""Public claim budget for Memory Firewall."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClaimBudget:
    """What the current public artifact may and may not claim."""

    allowed: tuple[str, ...]
    not_allowed: tuple[str, ...]
    current_scope: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "allowed": list(self.allowed),
            "not_allowed": list(self.not_allowed),
            "current_scope": list(self.current_scope),
        }


_CLAIM_BUDGET = ClaimBudget(
    allowed=(
        "Defines a canonical event surface for persistent memory writes.",
        "Defines deterministic event ids for adapter-emitted memory events.",
        "Defines deterministic finding ids and structured evidence spans.",
        "Defines an explainable risk taxonomy for memory-integrity findings.",
        "Defines an adapter capability report and local conformance probe.",
        "Defines deterministic policy recommendation vocabulary.",
        "Runs deterministic local detectors over supplied MemoryEvent JSON.",
        "Maps supplied MemoryEvent JSON into AMC candidate/evidence preview records.",
        "Flags low-authority contradictions before trusted-state handling.",
        "Scans finite normalized MemoryEvent JSONL files and watches normalized stdin JSONL streams.",
        "Maintains a local review queue for high-risk scan events.",
        "Emits deterministic allow/reject override receipts for local review decisions.",
        "Shows a local trusted-read preview over allowed review items without writing trusted state.",
        "Runs a deterministic local poisoning demo over a toy last-write-wins memory store.",
        "Runs a bounded custom SQLite reference proxy in observe, overlay, and enforce modes.",
        "Shows enforce-mode suppression only for the built-in reference proxy substrate.",
        "Generates a local static integrity report and redacted share export.",
        "Provides an observe-only Hermes hook alpha for high-signal memory write diagnostics.",
        "Writes local Hermes Memory Firewall diagnostics without replacing the active memory provider.",
        "Installs a Hermes user-plugin shim that delegates to the installed Memory Firewall package.",
        "Shows redacted recent Hermes observation summaries without printing raw candidate memory text.",
        "Runs a local Hermes setup checkup over plugin shim, plugins.enabled config hints, diagnostics permissions, and recent observations.",
        "Generates a local redacted Hermes diagnostics report over observe-only adapter observations.",
        "Reports provenance-only untrusted memory writes as WARN while preserving HIGH-RISK for contradictions and stricter detector findings.",
        "Reports current-version versus legacy or unknown-version Hermes observation counts without rewriting historical diagnostics.",
        "Provides a generic observe-only local adapter bridge over one supplied memory candidate.",
        "Shows redacted generic adapter observation summaries without printing raw candidate memory text.",
        "Generates a local redacted generic adapter diagnostics report over observe-only bridge observations.",
        "Provides a generic Python write-through helper for caller-owned memory write functions.",
        "Provides an installable local SQLite write-through diagnostic that preserves native writes while producing redacted Memory Firewall observations and a local report.",
        "Generates stage-aware candidate lineage reports over supplied evidence packets.",
        "Flags downstream-used memory candidates that are unscanned, weakly linked, scope-mismatched, case-level-only, or not escalated enough for downstream use.",
        "Provides machine-readable schemas and a CLI for inspecting the contract.",
        "Depends on compatible agent-memory-contracts 1.3.x as the public trust-kernel layer.",
    ),
    not_allowed=(
        "Does not determine objective truth.",
        "Does not secure an entire agent.",
        "Does not stop every memory-poisoning attack.",
        "Detector findings are heuristic signals, not proof of adversarial intent.",
        "State analysis is a reducer-review signal, not trusted-memory approval.",
        "Does not broadly scan real stores or connect to arbitrary live memory substrates yet.",
        "Does not enforce quarantine, suppression, or adapter write blocking yet.",
        "Does not write trusted ledger entries or state snapshots.",
        "Does not claim framework adapter support beyond the observe-only Hermes hook alpha.",
        "The Hermes hook alpha does not replace, wrap, or suppress the active Hermes memory provider.",
        "The Hermes plugin shim does not patch Hermes, configure a memory provider, or add enforcement.",
        "The Hermes observations CLI is not a raw trace export or approved-memory ledger.",
        "The Hermes checkup CLI is not proof that Hermes runtime enforcement or provider suppression is active.",
        "The Hermes report CLI is not a raw trace export, approved-memory ledger, hosted dashboard, telemetry service, or enforcement audit.",
        "Hermes version-aware diagnostics do not migrate, rewrite, delete, or reclassify historical rows.",
        "The generic adapter bridge does not scan existing memory stores or runtime histories.",
        "The generic adapter bridge does not replace, wrap, configure, suppress, or approve writes for production memory providers.",
        "The generic adapter bridge is not Mem0, Honcho, GBrain, LangChain, Letta, Zep, Hermes, vector-store, or production provider support.",
        "The generic adapter report CLI is not a raw trace export, approved-memory ledger, hosted dashboard, telemetry service, provider wrapper, or enforcement audit.",
        "The generic write-through helper does not replace, wrap, configure, suppress, retry, approve, or secure production memory providers.",
        "The generic write-through helper result does not include raw writer return values or exception messages.",
        "The SQLite write-through diagnostic is not a live provider adapter, hosted service, prevention layer, provider vulnerability proof, or production enforcement mechanism.",
        "Lineage reports do not prove verified provenance, objective truth, exploitability of a named live provider, or production enforcement.",
        "The public authority-boundary lineage example is a synthetic fixture, not a live Mem0, GBrain, Hermes, Honcho, LangChain, Letta, Zep, vector-store, or hosted-provider exploit.",
        "The poisoning demo is not a benchmark and does not represent a real memory framework.",
        "The reference proxy is not Mem0, Hermes, GBrain, LangChain, Letta, Zep, or vector-store support.",
        "Reference enforce mode does not secure native memory outside the controlled SQLite substrate.",
        "Does not run a hosted dashboard, telemetry service, auth system, or billing system.",
        "Redacted report export is not a raw trace export.",
    ),
    current_scope=(
        "Package shell.",
        "CLI shell.",
        "Canonical MemoryEvent model.",
        "Deterministic event id helper.",
        "MemoryFinding model shape.",
        "Deterministic finding id helper.",
        "Structured EvidenceSpan model.",
        "Deterministic policy recommendation model.",
        "Built-in deterministic detector pack.",
        "AMC candidate/evidence preview mapping.",
        "Local state assertion analysis.",
        "Contradiction and supersession-candidate checks.",
        "Normalized JSONL scan.",
        "Normalized stdin watch.",
        "Local review queue.",
        "Local allow/reject override receipts.",
        "Trusted-read preview over allowed review items.",
        "Deterministic local poisoning demo.",
        "Custom SQLite reference proxy.",
        "Reference observe, overlay, and enforce modes.",
        "Local static report.",
        "Redacted report export.",
        "Observe-only Hermes hook alpha.",
        "Hermes user-plugin shim installer.",
        "Hermes diagnostics JSONL.",
        "Hermes status CLI.",
        "Hermes observations CLI.",
        "Hermes observations schema.",
        "Hermes checkup CLI.",
        "Hermes checkup schema.",
        "Hermes report CLI.",
        "Hermes report schema.",
        "Signal-level calibration for provenance-only memory writes.",
        "Current-vs-legacy Hermes diagnostics readout.",
        "Generic local adapter bridge.",
        "Generic adapter observations CLI.",
        "Generic adapter report CLI.",
        "Generic Python write-through helper.",
        "Local SQLite write-through diagnostic CLI.",
        "Generic adapter observe-result, observations, write-through result, and report schemas.",
        "Stage-aware lineage report CLI and schema.",
        "Public authority-boundary lineage fixture.",
        "Adapter capability report.",
        "Built-in fake adapter conformance probe.",
        "Risk taxonomy.",
        "Claim budget and non-claims.",
        "CI and review packet.",
    ),
)


def claim_budget() -> ClaimBudget:
    """Return the current public claim budget."""

    return _CLAIM_BUDGET
