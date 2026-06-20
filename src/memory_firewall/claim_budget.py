"""Public claim budget for Memory Firewall."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClaimBudget:
    """What the current public artifact may and may not claim."""

    allowed: tuple[str, ...]
    not_allowed: tuple[str, ...]
    mf01_scope: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "allowed": list(self.allowed),
            "not_allowed": list(self.not_allowed),
            "mf01_scope": list(self.mf01_scope),
        }


_CLAIM_BUDGET = ClaimBudget(
    allowed=(
        "Defines a canonical event surface for persistent memory writes.",
        "Defines an explainable risk taxonomy for memory-integrity findings.",
        "Provides machine-readable schemas and a CLI for inspecting the contract.",
        "Depends on compatible agent-memory-contracts 1.3.x as the public trust-kernel layer.",
    ),
    not_allowed=(
        "Does not determine objective truth.",
        "Does not secure an entire agent.",
        "Does not stop every memory-poisoning attack.",
        "Does not scan real stores yet.",
        "Does not quarantine or enforce yet.",
        "Does not claim framework adapter support yet.",
    ),
    mf01_scope=(
        "Package shell.",
        "CLI shell.",
        "Canonical MemoryEvent model.",
        "MemoryFinding model shape.",
        "Risk taxonomy.",
        "Claim budget and non-claims.",
        "CI and review packet.",
    ),
)


def claim_budget() -> ClaimBudget:
    """Return the current public claim budget."""

    return _CLAIM_BUDGET
