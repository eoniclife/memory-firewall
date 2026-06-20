from memory_firewall import claim_budget, event_schema, finding_schema, risk_taxonomy
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
    assert bundle["schema_version"] == "mf-01"
    assert bundle["claim_budget"]["allowed"] == list(budget.allowed)
    assert any("Does not scan real stores yet" in item for item in budget.not_allowed)
