import json
from pathlib import Path

from jsonschema import Draft202012Validator

from memory_firewall import (
    REDACTED_EXPORT_FILENAME,
    REPORT_HTML_FILENAME,
    REPORT_JSON_FILENAME,
    REPORT_VERSION,
    ReportBundle,
    generate_demo_report,
    redacted_report_export_schema,
    report_result_schema,
    write_report_bundle,
)


def test_generate_demo_report_summarizes_demo_and_proxy_paths() -> None:
    report = generate_demo_report()
    payload = report.to_dict()

    assert report.report_version == REPORT_VERSION
    assert payload["summary"]["high_risk_events"] == 1
    assert payload["summary"]["queued_items"] == 1
    assert payload["summary"]["suppressed_native_writes"] == 1
    assert payload["summary"]["hosted_dashboard"] is False
    assert payload["summary"]["production_adapter_support"] is False
    assert [item["mode"] for item in payload["proxy_outcomes"]] == [
        "observe",
        "overlay",
        "enforce",
    ]
    assert payload["proxy_outcomes"][2]["native_answer"] == "Helio"
    assert payload["event_summaries"][1]["suppressed_native_write"] is True
    Draft202012Validator(report_result_schema()).validate(payload)


def test_redacted_export_omits_answer_values_and_stable_ids(tmp_path: Path) -> None:
    report = generate_demo_report()
    redacted = write_report_bundle(report, tmp_path / "report").redacted_export
    payload = redacted.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["redacted"] is True
    assert "Helio" not in encoded
    assert "Mirage" not in encoded
    assert "mfev_v1_" not in encoded
    assert "mfrevitem_v1_" not in encoded
    assert payload["demo_outcome"]["answer_values_redacted"] is True
    assert payload["demo_outcome"]["event_ids_redacted"] is True
    Draft202012Validator(redacted_report_export_schema()).validate(payload)


def test_write_report_bundle_is_deterministic_and_local(tmp_path: Path) -> None:
    report = generate_demo_report()
    first = write_report_bundle(report, tmp_path / "first")
    second = write_report_bundle(report, tmp_path / "second")

    assert isinstance(first, ReportBundle)
    assert first.report_json_path.name == REPORT_JSON_FILENAME
    assert first.html_path.name == REPORT_HTML_FILENAME
    assert first.redacted_export_path.name == REDACTED_EXPORT_FILENAME
    assert first.report_json_path.read_text(encoding="utf-8") == (
        second.report_json_path.read_text(encoding="utf-8")
    )
    assert first.redacted_export_path.read_text(encoding="utf-8") == (
        second.redacted_export_path.read_text(encoding="utf-8")
    )
    html = first.html_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "Memory Firewall Local Integrity Report" in html
    assert "https://" not in html

    bundle_payload = first.to_dict()
    encoded_bundle = json.dumps(bundle_payload, sort_keys=True)
    assert "report" not in bundle_payload
    assert "Helio" not in encoded_bundle
    assert "Mirage" not in encoded_bundle
    assert "mfev_v1_" not in encoded_bundle
