from typing import Any, cast

from memory_firewall import (
    EvidenceField,
    EvidenceSpan,
    MemoryFinding,
    PolicyConfig,
    PolicyRecommendation,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    baseline_disposition_for_severity,
    max_disposition,
    recommend_policy,
)


def _finding(
    *,
    severity: RiskSeverity = RiskSeverity.SUSPICIOUS,
    confidence: float = 0.8,
    recommended: RecommendedDisposition = RecommendedDisposition.WARN,
) -> MemoryFinding:
    return MemoryFinding.from_detector_payload(
        {
            "event_id": "mfev_v1_test",
            "risk_category": RiskCategory.PROVENANCE_GAP.value,
            "severity": severity.value,
            "confidence": confidence,
            "evidence_span": EvidenceSpan(
                source_field=EvidenceField.PROPOSED_MEMORY,
                start=0,
                end=4,
                quote="test",
            ).to_dict(),
            "detector_name": "policy-test",
            "detector_version": "0.1.0",
            "explanation": "Policy test finding.",
            "recommended_disposition": recommended.value,
            "limitations": [],
        }
    )


def test_disposition_ordering_is_explicit() -> None:
    assert max_disposition(
        RecommendedDisposition.WARN, RecommendedDisposition.REVIEW
    ) == RecommendedDisposition.REVIEW
    assert baseline_disposition_for_severity(
        RiskSeverity.INFORMATIONAL
    ) == RecommendedDisposition.PASS
    assert baseline_disposition_for_severity(
        RiskSeverity.HIGH_IMPACT
    ) == RecommendedDisposition.REVIEW


def test_policy_recommendation_is_deterministic() -> None:
    finding = _finding()
    first = recommend_policy(finding)
    second = recommend_policy(MemoryFinding.from_dict(finding.to_dict()))

    assert first == second
    assert first.recommended_disposition == RecommendedDisposition.REVIEW
    assert "confidence:suspicious_review_threshold" in first.reason_codes


def test_policy_escalates_high_impact_high_confidence_to_quarantine() -> None:
    finding = _finding(
        severity=RiskSeverity.HIGH_IMPACT,
        confidence=0.95,
        recommended=RecommendedDisposition.REVIEW,
    )
    recommendation = recommend_policy(finding)

    assert recommendation.recommended_disposition == RecommendedDisposition.QUARANTINE
    assert "confidence:high_impact_quarantine_threshold" in (
        recommendation.reason_codes
    )


def test_policy_config_metadata_is_immutable() -> None:
    metadata = {"trace": "one"}
    config = PolicyConfig(metadata=metadata)
    metadata["trace"] = "changed"

    assert config.to_dict()["metadata"] == {"trace": "one"}
    try:
        cast(Any, config.metadata)["new"] = "nope"
    except TypeError:
        pass
    else:
        raise AssertionError("PolicyConfig metadata remained mutable")


def test_policy_recommendation_rejects_string_reason_codes() -> None:
    try:
        PolicyRecommendation(
            finding_id="mffind_v1_test",
            recommended_disposition=RecommendedDisposition.REVIEW,
            reason_codes="not-a-tuple",  # type: ignore[arg-type]
        )
    except TypeError as exc:
        assert "reason_codes" in str(exc)
    else:
        raise AssertionError("PolicyRecommendation accepted string reason_codes")


def test_policy_config_rejects_invalid_threshold_order() -> None:
    try:
        PolicyConfig(
            suspicious_review_confidence=0.95,
            high_impact_quarantine_confidence=0.9,
        )
    except ValueError as exc:
        assert "less than or equal" in str(exc)
    else:
        raise AssertionError("PolicyConfig accepted inverted thresholds")
