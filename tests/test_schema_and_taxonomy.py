from typing import Any

from jsonschema import Draft202012Validator

from memory_firewall import (
    EvidenceField,
    EvidenceSpan,
    MemoryEvent,
    MemoryFinding,
    MemoryOperation,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    SourceType,
    adapter_capability_report_schema,
    claim_budget,
    default_detector_pack,
    demo_memory_adapter,
    detector_pack_schema,
    detector_result_schema,
    evidence_span_schema,
    event_schema,
    finding_schema,
    policy_schema,
    risk_taxonomy,
)
from memory_firewall.schema import schema_bundle


def _policy_contract_payload() -> dict[str, Any]:
    return {
        "policy_version": "mf-03",
        "severity_order": ["informational", "suspicious", "high_impact"],
        "disposition_order": ["pass", "warn", "review", "quarantine"],
        "config_schema": {
            "suspicious_review_confidence": 0.75,
            "high_impact_quarantine_confidence": 0.9,
            "metadata": {},
        },
        "recommendation_schema": {
            "finding_id": "mffind_v1_test",
            "recommended_disposition": "review",
            "reason_codes": ["severity:suspicious"],
            "policy_version": "mf-03",
        },
    }


def test_event_schema_contains_required_contract_fields() -> None:
    schema = event_schema()
    required = set(schema["required"])
    assert "event_id" in required
    assert "proposed_memory" in required
    assert "source_authority" in required
    assert schema["properties"]["source_type"]["enum"]


def test_finding_schema_uses_frozen_risk_taxonomy() -> None:
    schema = finding_schema()
    categories = set(schema["properties"]["risk_category"]["enum"])
    taxonomy = {item.key.value for item in risk_taxonomy()}
    assert categories == taxonomy
    assert "instruction_injection" in categories
    assert "procedural_poisoning" in categories


def test_schema_bundle_includes_claim_budget() -> None:
    bundle = schema_bundle()
    budget = claim_budget()
    assert bundle["schema_version"] == "mf-04"
    assert bundle["claim_budget"]["allowed"] == list(budget.allowed)
    assert any("Does not scan real stores yet" in item for item in budget.not_allowed)
    assert "adapter_capability_report_schema" in bundle
    assert "policy_schema" in bundle
    assert "detector_pack_schema" in bundle
    assert "detector_result_schema" in bundle
    assert bundle["default_detector_pack"]["version"] == "mf-04"


def test_model_outputs_validate_against_exported_schemas() -> None:
    event = MemoryEvent(
        event_id="evt_schema",
        timestamp="2026-06-20T14:00:00Z",
        actor="agent:test",
        user_or_tenant_scope="tenant:demo",
        source_type=SourceType.TOOL_OUTPUT,
        source_id="tool_001",
        source_authority=SourceAuthority.TOOL_OBSERVED,
        raw_or_redacted_content="The CRM returned owner Alice.",
        proposed_memory="Account owner is Alice.",
        operation=MemoryOperation.UPSERT,
        target_namespace="crm",
        metadata={"trace_id": "trace_schema"},
    )
    finding = MemoryFinding(
        finding_id="find_schema",
        event_id="evt_schema",
        risk_category=RiskCategory.PROVENANCE_GAP,
        severity=RiskSeverity.INFORMATIONAL,
        confidence=0.2,
        evidence_span=EvidenceSpan(
            source_field=EvidenceField.PROPOSED_MEMORY,
            start=0,
            end=len("Account owner"),
            quote="Account owner",
        ),
        detector_name="schema-test",
        detector_version="0.1.0",
        explanation="Schema validation smoke.",
        recommended_disposition=RecommendedDisposition.PASS,
    )

    Draft202012Validator.check_schema(event_schema())
    Draft202012Validator.check_schema(evidence_span_schema())
    Draft202012Validator.check_schema(finding_schema())
    Draft202012Validator.check_schema(adapter_capability_report_schema())
    Draft202012Validator.check_schema(policy_schema())
    Draft202012Validator.check_schema(detector_pack_schema())
    Draft202012Validator.check_schema(detector_result_schema())
    Draft202012Validator(event_schema()).validate(event.to_dict())
    Draft202012Validator(evidence_span_schema()).validate(
        finding.evidence_span.to_dict()
    )
    Draft202012Validator(finding_schema()).validate(finding.to_dict())
    Draft202012Validator(adapter_capability_report_schema()).validate(
        demo_memory_adapter().capability_report.to_dict()
    )
    Draft202012Validator(detector_pack_schema()).validate(
        default_detector_pack().to_dict()
    )


def test_detector_pack_schema_rejects_mislabeled_builtin_definition() -> None:
    payload: dict[str, Any] = default_detector_pack().to_dict()
    definitions = list(payload["definitions"])
    first_definition = dict(definitions[0])
    definitions[0] = {
        **first_definition,
        "risk_category": "contradiction",
    }
    payload["definitions"] = definitions

    errors = list(Draft202012Validator(detector_pack_schema()).iter_errors(payload))

    assert errors


def test_adapter_schema_rejects_supported_and_unsupported_overlap() -> None:
    payload = demo_memory_adapter().capability_report.to_dict()
    payload["unsupported_capabilities"].append("emit_memory_events")

    errors = list(
        Draft202012Validator(adapter_capability_report_schema()).iter_errors(payload)
    )

    assert errors


def test_policy_schema_accepts_canonical_policy_contract_payload() -> None:
    Draft202012Validator(policy_schema()).validate(_policy_contract_payload())


def test_evidence_span_schema_rejects_empty_or_out_of_bounds_spans() -> None:
    validator = Draft202012Validator(evidence_span_schema())
    empty_errors = list(
        validator.iter_errors(
            {
                "source_field": "proposed_memory",
                "start": 0,
                "end": 0,
                "quote": "",
            }
        )
    )
    out_of_bounds_errors = list(
        validator.iter_errors(
            {
                "source_field": "proposed_memory",
                "start": 16_384,
                "end": 16_385,
                "quote": "x",
            }
        )
    )

    assert empty_errors
    assert out_of_bounds_errors


def test_policy_schema_rejects_empty_reason_codes() -> None:
    payload = _policy_contract_payload()
    payload["recommendation_schema"] = {
        **payload["recommendation_schema"],
        "reason_codes": [],
    }

    errors = list(Draft202012Validator(policy_schema()).iter_errors(payload))

    assert errors


def test_policy_schema_freezes_order_arrays() -> None:
    payload = _policy_contract_payload()
    payload["severity_order"] = ["suspicious", "informational", "high_impact"]

    errors = list(Draft202012Validator(policy_schema()).iter_errors(payload))

    assert errors


def test_policy_schema_mirrors_metadata_limits() -> None:
    payload = _policy_contract_payload()
    payload["config_schema"] = {
        **payload["config_schema"],
        "metadata": {f"k{i}": "v" for i in range(65)},
    }

    errors = list(Draft202012Validator(policy_schema()).iter_errors(payload))

    assert errors
