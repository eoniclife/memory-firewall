"""Risk taxonomy for the MF-01 product contract."""

from __future__ import annotations

from dataclasses import dataclass

from .models import RiskCategory


@dataclass(frozen=True, slots=True)
class RiskCategoryDefinition:
    """Human-readable definition for a risk category."""

    key: RiskCategory
    name: str
    question: str
    non_claim: str

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key.value,
            "name": self.name,
            "question": self.question,
            "non_claim": self.non_claim,
        }


_RISK_TAXONOMY: tuple[RiskCategoryDefinition, ...] = (
    RiskCategoryDefinition(
        RiskCategory.PROVENANCE_GAP,
        "Provenance gap",
        "Does this memory lack an inspectable source or custody chain?",
        "A provenance gap is not proof that the memory is false.",
    ),
    RiskCategoryDefinition(
        RiskCategory.INSTRUCTION_INJECTION,
        "Instruction injection",
        "Does content try to persist instructions, overrides, or hidden policy?",
        "Pattern detection is not universal prompt-injection prevention.",
    ),
    RiskCategoryDefinition(
        RiskCategory.AUTHORITY_OR_IDENTITY_CHANGE,
        "Authority or identity change",
        "Does this alter who has authority, ownership, payment, or identity?",
        "High-impact changes still need application-specific validation.",
    ),
    RiskCategoryDefinition(
        RiskCategory.CONTRADICTION,
        "Contradiction",
        "Does this conflict with a known trusted memory or source?",
        "A conflict does not decide which claim is correct.",
    ),
    RiskCategoryDefinition(
        RiskCategory.TEMPORAL_OR_STALE_STATE,
        "Temporal or stale state",
        "Does this store time-sensitive state without enough dating?",
        "Staleness risk is not a claim about present truth.",
    ),
    RiskCategoryDefinition(
        RiskCategory.SCOPE_OR_PRIVACY_VIOLATION,
        "Scope or privacy violation",
        "Does this memory cross tenant, user, project, or privacy boundaries?",
        "This is not a substitute for a complete privacy program.",
    ),
    RiskCategoryDefinition(
        RiskCategory.PROCEDURAL_POISONING,
        "Procedural poisoning",
        "Does this record unsafe experience as a successful method?",
        "It does not prove adversarial intent without surrounding evidence.",
    ),
    RiskCategoryDefinition(
        RiskCategory.ANOMALOUS_PERSISTENCE,
        "Anomalous persistence",
        "Does this memory look unusually repetitive, durable, or out of place?",
        "Anomaly detection is advisory unless backed by a deterministic policy.",
    ),
)


def risk_taxonomy() -> tuple[RiskCategoryDefinition, ...]:
    """Return the frozen MF-01 risk taxonomy."""

    return _RISK_TAXONOMY
