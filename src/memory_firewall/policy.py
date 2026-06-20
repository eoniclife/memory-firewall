"""Deterministic policy recommendations for Memory Firewall findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .models import (
    JSONScalar,
    MemoryFinding,
    RecommendedDisposition,
    RiskSeverity,
    _coerce_metadata,
    _freeze_metadata,
    _require_probability,
    _require_string,
)

SEVERITY_ORDER: Mapping[RiskSeverity, int] = {
    RiskSeverity.INFORMATIONAL: 0,
    RiskSeverity.SUSPICIOUS: 1,
    RiskSeverity.HIGH_IMPACT: 2,
}

DISPOSITION_ORDER: Mapping[RecommendedDisposition, int] = {
    RecommendedDisposition.PASS: 0,
    RecommendedDisposition.WARN: 1,
    RecommendedDisposition.REVIEW: 2,
    RecommendedDisposition.QUARANTINE: 3,
}

POLICY_VERSION = "mf-03"


def max_disposition(
    left: RecommendedDisposition, right: RecommendedDisposition
) -> RecommendedDisposition:
    """Return the stricter of two dispositions."""

    return left if DISPOSITION_ORDER[left] >= DISPOSITION_ORDER[right] else right


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Deterministic thresholds for local policy recommendations."""

    suspicious_review_confidence: float = 0.75
    high_impact_quarantine_confidence: float = 0.9
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "suspicious_review_confidence",
            _require_probability(
                self.suspicious_review_confidence,
                "suspicious_review_confidence",
            ),
        )
        object.__setattr__(
            self,
            "high_impact_quarantine_confidence",
            _require_probability(
                self.high_impact_quarantine_confidence,
                "high_impact_quarantine_confidence",
            ),
        )
        if self.suspicious_review_confidence > self.high_impact_quarantine_confidence:
            raise ValueError(
                "suspicious_review_confidence must be less than or equal to "
                "high_impact_quarantine_confidence"
            )
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable policy config."""

        return {
            "suspicious_review_confidence": self.suspicious_review_confidence,
            "high_impact_quarantine_confidence": self.high_impact_quarantine_confidence,
            "metadata": _coerce_metadata(
                {} if self.metadata is None else self.metadata
            ),
        }


@dataclass(frozen=True, slots=True)
class PolicyRecommendation:
    """Inspectable deterministic recommendation for one finding."""

    finding_id: str
    recommended_disposition: RecommendedDisposition
    reason_codes: tuple[str, ...]
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        _require_string(self.finding_id, "finding_id", allow_empty=False, max_chars=96)
        if not isinstance(self.recommended_disposition, RecommendedDisposition):
            raise TypeError(
                "recommended_disposition must be a RecommendedDisposition"
            )
        if isinstance(self.reason_codes, str) or not isinstance(self.reason_codes, tuple):
            raise TypeError("reason_codes must be a tuple of strings")
        if any(not isinstance(item, str) for item in self.reason_codes):
            raise TypeError("reason_codes must contain only strings")
        if any(not item for item in self.reason_codes):
            raise ValueError("reason_codes must not contain empty strings")
        _require_string(
            self.policy_version,
            "policy_version",
            allow_empty=False,
            max_chars=64,
        )
        if self.policy_version != POLICY_VERSION:
            raise ValueError(f"policy_version must be {POLICY_VERSION}")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable policy recommendation."""

        return {
            "finding_id": self.finding_id,
            "recommended_disposition": self.recommended_disposition.value,
            "reason_codes": list(self.reason_codes),
            "policy_version": self.policy_version,
        }


def baseline_disposition_for_severity(
    severity: RiskSeverity,
) -> RecommendedDisposition:
    """Return the minimum disposition for a severity."""

    if severity == RiskSeverity.INFORMATIONAL:
        return RecommendedDisposition.PASS
    if severity == RiskSeverity.SUSPICIOUS:
        return RecommendedDisposition.WARN
    if severity == RiskSeverity.HIGH_IMPACT:
        return RecommendedDisposition.REVIEW
    raise ValueError(f"unsupported severity: {severity}")


def recommend_policy(
    finding: MemoryFinding, config: PolicyConfig | None = None
) -> PolicyRecommendation:
    """Return a deterministic policy recommendation for a finding."""

    active_config = config or PolicyConfig()
    reasons: list[str] = []
    disposition = baseline_disposition_for_severity(finding.severity)
    reasons.append(f"severity:{finding.severity.value}")

    if (
        finding.severity == RiskSeverity.SUSPICIOUS
        and finding.confidence >= active_config.suspicious_review_confidence
    ):
        disposition = max_disposition(disposition, RecommendedDisposition.REVIEW)
        reasons.append("confidence:suspicious_review_threshold")

    if (
        finding.severity == RiskSeverity.HIGH_IMPACT
        and finding.confidence >= active_config.high_impact_quarantine_confidence
    ):
        disposition = max_disposition(disposition, RecommendedDisposition.QUARANTINE)
        reasons.append("confidence:high_impact_quarantine_threshold")

    disposition = max_disposition(disposition, finding.recommended_disposition)
    reasons.append(f"finding_recommended:{finding.recommended_disposition.value}")

    return PolicyRecommendation(
        finding_id=finding.finding_id,
        recommended_disposition=disposition,
        reason_codes=tuple(reasons),
    )
