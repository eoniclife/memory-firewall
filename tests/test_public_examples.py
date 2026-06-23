import json
from pathlib import Path

from jsonschema import Draft202012Validator

from memory_firewall import claim_budget, generate_lineage_report, lineage_report_schema


def test_authority_boundary_lineage_example_is_a_real_diagnostic() -> None:
    packet_path = Path(__file__).resolve().parents[1] / "examples" / "authority_boundary_lineage.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    report = generate_lineage_report(packet)
    payload = report.to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}
    verdict = payload["candidate_verdicts"][0]

    assert payload["provider"] == "memory-firewall-public-fixture"
    assert payload["summary"]["downstream_used_candidates"] == 1
    assert payload["summary"]["downstream_used_candidates_escalated"] == 0
    assert "downstream_candidate_not_escalated" in issue_codes
    assert verdict["scan_status"] == "candidate_level"
    assert verdict["persisted"] is True
    assert verdict["retrieved"] is True
    assert verdict["downstream_used"] is True
    assert verdict["declared_authority"] == "untrusted"
    assert verdict["memory_firewall_disposition"] == "warn"
    Draft202012Validator(lineage_report_schema()).validate(payload)


def test_claim_budget_covers_public_lineage_boundary() -> None:
    budget = claim_budget()

    assert any("stage-aware candidate lineage" in item for item in budget.allowed)
    assert any("downstream-used memory candidates" in item for item in budget.allowed)
    assert any("synthetic fixture" in item for item in budget.not_allowed)
