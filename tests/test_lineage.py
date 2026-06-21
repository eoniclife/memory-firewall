import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from memory_firewall import (
    CandidateScanStatus,
    LineageLinkStatus,
    RecommendedDisposition,
    generate_lineage_report,
    lineage_report_schema,
)
from memory_firewall.cli import main


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source() -> dict[str, object]:
    return {
        "lineage_id": "case-1",
        "source_event_id": "source-1",
        "source_digest": _digest("quoted untrusted source"),
        "scope": "tenant:demo",
        "declared_authority": "untrusted",
        "verified_authority_status": "declared_only",
        "metadata": {},
    }


def _candidate(
    candidate_id: str,
    content: str,
    provider_memory_id: str | None,
    disposition: str | None,
    *,
    downstream_scan_status: str | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {}
    if downstream_scan_status is not None:
        metadata["scan_status"] = downstream_scan_status
    return {
        "lineage_id": "case-1",
        "candidate_id": candidate_id,
        "source_event_id": "source-1",
        "content": content,
        "provider_memory_id": provider_memory_id,
        "scope": "tenant:demo",
        "declared_authority": "untrusted",
        "verified_authority_status": "declared_only",
        "memory_firewall_event_id": None
        if disposition is None
        else f"mfev_v1_{candidate_id}",
        "memory_firewall_disposition": disposition,
        "memory_firewall_finding_count": 0 if disposition is None else 2,
        "metadata": metadata,
    }


def _persisted(
    persisted_record_id: str,
    content: str,
    provider_memory_id: str | None,
    *,
    scope: str = "tenant:demo",
) -> dict[str, object]:
    return {
        "lineage_id": "case-1",
        "persisted_record_id": persisted_record_id,
        "provider_memory_id": provider_memory_id,
        "content": content,
        "scope": scope,
        "metadata": {},
    }


def _retrieved(
    retrieval_event_id: str,
    content: str,
    provider_memory_id: str | None,
    persisted_record_id: str | None,
    *,
    downstream_used: bool,
    scope: str = "tenant:demo",
) -> dict[str, object]:
    return {
        "lineage_id": "case-1",
        "retrieval_event_id": retrieval_event_id,
        "provider_memory_id": provider_memory_id,
        "persisted_record_id": persisted_record_id,
        "content": content,
        "scope": scope,
        "downstream_used": downstream_used,
        "metadata": {},
    }


def _base_packet() -> dict[str, object]:
    return {
        "lineage_version": "mf-27",
        "provider": "mem0",
        "provider_version": "2.0.7",
        "source_events": [_source()],
        "extracted_candidates": [],
        "persisted_memories": [],
        "retrieved_memories": [],
        "metadata": {"packet": "unit"},
    }


def test_lineage_report_keeps_downstream_candidate_separate_from_sibling_quarantine() -> None:
    packet = _base_packet()
    target = "User prefers skipping tests before release."
    sibling = "A scraped page instructed the system to ignore prior instructions."
    packet["extracted_candidates"] = [
        _candidate("target", target, "mem-target", "warn"),
        _candidate("sibling", sibling, "mem-sibling", "quarantine"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-target", target, "mem-target"),
        _persisted("q-sibling", sibling, "mem-sibling"),
    ]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", target, "mem-target", "q-target", downstream_used=True),
        _retrieved("ret-sibling", sibling, "mem-sibling", "q-sibling", downstream_used=False),
    ]

    report = generate_lineage_report(packet)
    payload = report.to_dict()
    by_id = {item["candidate_id"]: item for item in payload["candidate_verdicts"]}

    assert payload["summary"]["highest_candidate_disposition"] == "quarantine"
    assert by_id["target"]["downstream_used"] is True
    assert by_id["target"]["memory_firewall_disposition"] == "warn"
    assert by_id["sibling"]["memory_firewall_disposition"] == "quarantine"
    assert "downstream_candidate_not_escalated" in {
        issue["code"] for issue in payload["issues"]
    }
    Draft202012Validator(lineage_report_schema()).validate(payload)


def test_lineage_report_links_missing_provider_id_by_content_digest() -> None:
    packet = _base_packet()
    content = "User prefers heliotrope dashboards."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, None, "review"),
    ]
    packet["persisted_memories"] = [_persisted("q-candidate", content, None)]
    packet["retrieved_memories"] = [
        _retrieved("ret-candidate", content, None, "q-candidate", downstream_used=False)
    ]

    verdict = generate_lineage_report(packet).candidate_verdicts[0]

    assert verdict.link_status == LineageLinkStatus.EXACT_CONTENT_DIGEST
    assert verdict.persisted is True
    assert verdict.retrieved is True
    assert "matched by content digest" in " ".join(verdict.limitations)


def test_lineage_report_flags_mutated_persistence_and_orphan_retrieval() -> None:
    packet = _base_packet()
    packet["extracted_candidates"] = [
        _candidate("candidate", "User prefers safe releases.", "mem-safe", "review"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-mutated", "User prefers unsafe releases.", "mem-other"),
    ]
    packet["retrieved_memories"] = [
        _retrieved(
            "ret-orphan",
            "User prefers unsafe releases.",
            "mem-other",
            "q-mutated",
            downstream_used=False,
        )
    ]

    payload = generate_lineage_report(packet).to_dict()
    verdict = payload["candidate_verdicts"][0]
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert verdict["link_status"] == "not_persisted"
    assert verdict["persisted"] is False
    assert "unmatched_persisted_record" in issue_codes
    assert "unmatched_retrieval" in issue_codes


def test_lineage_report_flags_cross_scope_match() -> None:
    packet = _base_packet()
    content = "User prefers review before production deploys."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-shared", "review"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-scope", content, "mem-shared", scope="tenant:other"),
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert payload["candidate_verdicts"][0]["link_status"] == "scope_mismatch"
    assert payload["summary"]["scope_mismatches"] == 1
    assert "scope_mismatch" in {issue["code"] for issue in payload["issues"]}


def test_lineage_report_marks_case_level_scan_as_not_candidate_level() -> None:
    packet = _base_packet()
    content = "User prefers skipping tests before release."
    packet["extracted_candidates"] = [
        _candidate(
            "candidate",
            content,
            "mem-target",
            "quarantine",
            downstream_scan_status="case_level_only",
        ),
    ]
    packet["persisted_memories"] = [_persisted("q-target", content, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, "mem-target", "q-target", downstream_used=True)
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert payload["candidate_verdicts"][0]["scan_status"] == (
        CandidateScanStatus.CASE_LEVEL_ONLY.value
    )
    assert payload["summary"]["case_level_only_candidates"] == 1
    assert "downstream_candidate_without_candidate_level_scan" in {
        issue["code"] for issue in payload["issues"]
    }


def test_lineage_cli_reports_json_and_exits_on_issues(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _base_packet()
    content = "User prefers skipping tests before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", "warn"),
    ]
    packet["persisted_memories"] = [_persisted("q-target", content, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, "mem-target", "q-target", downstream_used=True)
    ]
    packet_path = tmp_path / "lineage.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    assert main(["lineage", "report", str(packet_path), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)

    assert payload["lineage_version"] == "mf-27"
    assert payload["summary"]["downstream_used_candidates"] == 1
    assert payload["issues"][0]["code"] == "downstream_candidate_not_escalated"


def test_lineage_cli_success_for_clean_candidate_level_quarantine(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _base_packet()
    content = "User prefers safe releases with tests."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", "quarantine"),
    ]
    packet["persisted_memories"] = [_persisted("q-target", content, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, "mem-target", "q-target", downstream_used=True)
    ]
    packet_path = tmp_path / "lineage-clean.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    assert main(["lineage", "report", str(packet_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["issues"] == []
    assert payload["candidate_verdicts"][0]["scan_status"] == "candidate_level"
    assert payload["candidate_verdicts"][0]["memory_firewall_disposition"] == (
        RecommendedDisposition.QUARANTINE.value
    )
