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
        "Hermes diagnostics JSONL.",
        "Hermes status CLI.",
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
