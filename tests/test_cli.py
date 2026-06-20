import json

from memory_firewall.cli import main


def test_schema_bundle_command_prints_json(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["schema", "bundle"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["package"] == "memory-firewall"
    assert payload["schema_version"] == "mf-02"


def test_adapter_schema_command_prints_json(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["schema", "adapter"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["title"] == "AdapterCapabilityReport"


def test_risks_json_command(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["risks", "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert any(item["key"] == "provenance_gap" for item in payload)


def test_claims_text_command(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["claims"]) == 0
    captured = capsys.readouterr()
    assert "Allowed claims:" in captured.out
    assert "Non-claims:" in captured.out


def test_conformance_demo_json_command(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["conformance", "demo", "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["passed"] is True
    assert payload["capability_report"]["adapter_name"] == "memory-firewall-demo"
    assert any(check["name"] == "stable_event_ids" for check in payload["checks"])
