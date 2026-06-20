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
        "Provides machine-readable schemas and a CLI for inspecting the contract.",
        "Depends on compatible agent-memory-contracts 1.3.x as the public trust-kernel layer.",
    ),
    not_allowed=(
        "Does not determine objective truth.",
        "Does not secure an entire agent.",
        "Does not stop every memory-poisoning attack.",
        "Detector findings are heuristic signals, not proof of adversarial intent.",
        "Does not scan real stores yet.",
        "Does not quarantine or enforce yet.",
        "Does not claim framework adapter support yet.",
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
