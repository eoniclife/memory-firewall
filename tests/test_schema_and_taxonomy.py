from jsonschema import Draft202012Validator

from memory_firewall import (
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
    demo_memory_adapter,
    event_schema,
    finding_schema,
    risk_taxonomy,
)
from memory_firewall.schema import schema_bundle


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
    assert bundle["schema_version"] == "mf-02"
    assert bundle["claim_budget"]["allowed"] == list(budget.allowed)
    assert any("Does not scan real stores yet" in item for item in budget.not_allowed)
    assert "adapter_capability_report_schema" in bundle


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
        evidence_span="The CRM returned owner Alice.",
        detector_name="schema-test",
        detector_version="0.1.0",
        explanation="Schema validation smoke.",
        recommended_disposition=RecommendedDisposition.PASS,
    )

    Draft202012Validator.check_schema(event_schema())
    Draft202012Validator.check_schema(finding_schema())
    Draft202012Validator.check_schema(adapter_capability_report_schema())
    Draft202012Validator(event_schema()).validate(event.to_dict())
    Draft202012Validator(finding_schema()).validate(finding.to_dict())
    Draft202012Validator(adapter_capability_report_schema()).validate(
        demo_memory_adapter().capability_report.to_dict()
    )
