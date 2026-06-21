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


def _scan(
    candidate_id: str | None,
    content: str,
    disposition: str,
    *,
    scan_level: str = "candidate_level",
    scope: str = "tenant:demo",
    event_id: str | None = None,
) -> dict[str, object]:
    event_suffix = "case" if candidate_id is None else candidate_id
    return {
        "lineage_id": "case-1",
        "memory_firewall_event_id": event_id or f"mfev_v1_{event_suffix}",
        "candidate_id": candidate_id,
        "scan_level": scan_level,
        "scanned_content": content,
        "scanned_scope": scope,
        "disposition": disposition,
        "finding_count": 2,
        "detector_pack_version": "mf-test",
        "policy_version": "mf-test",
        "metadata": {},
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
        "memory_firewall_scans": [],
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
    packet["memory_firewall_scans"] = [
        _scan("target", target, "warn"),
        _scan("sibling", sibling, "quarantine"),
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

    assert payload["summary"]["highest_any_candidate_disposition"] == "quarantine"
    assert payload["summary"]["highest_downstream_used_candidate_disposition"] == "warn"
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
    packet["memory_firewall_scans"] = [_scan("candidate", content, "review")]
    packet["persisted_memories"] = [_persisted("q-candidate", content, None)]
    packet["retrieved_memories"] = [
        _retrieved("ret-candidate", content, None, "q-candidate", downstream_used=False)
    ]

    verdict = generate_lineage_report(packet).candidate_verdicts[0]

    assert verdict.persisted_link_status == LineageLinkStatus.UNIQUE_CONTENT_DIGEST
    assert verdict.retrieval_link_status == (
        LineageLinkStatus.EXACT_PERSISTED_ID_AND_DIGEST
    )
    assert verdict.persisted is True
    assert verdict.retrieved is True
    assert "matched by unique exact content digest" in " ".join(verdict.limitations)


def test_lineage_report_flags_mutated_persistence_and_orphan_retrieval() -> None:
    packet = _base_packet()
    packet["extracted_candidates"] = [
        _candidate("candidate", "User prefers safe releases.", "mem-safe", "review"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate", "User prefers safe releases.", "review"),
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

    assert verdict["persisted_link_status"] == "not_linked"
    assert verdict["persisted"] is False
    assert "unmatched_persisted_record" in issue_codes
    assert "unmatched_retrieval" in issue_codes


def test_lineage_report_flags_cross_scope_match() -> None:
    packet = _base_packet()
    content = "User prefers review before production deploys."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-shared", "review"),
    ]
    packet["memory_firewall_scans"] = [_scan("candidate", content, "review")]
    packet["persisted_memories"] = [
        _persisted("q-scope", content, "mem-shared", scope="tenant:other"),
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert payload["candidate_verdicts"][0]["persisted_link_status"] == "scope_mismatch"
    assert payload["summary"]["scope_mismatches"] == 1
    assert "persisted_scope_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_lineage_report_flags_cross_scope_retrieval_match() -> None:
    packet = _base_packet()
    content = "User prefers review before production deploys."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-shared", "review"),
    ]
    packet["memory_firewall_scans"] = [_scan("candidate", content, "review")]
    packet["persisted_memories"] = [
        _persisted("q-candidate", content, "mem-shared"),
    ]
    packet["retrieved_memories"] = [
        _retrieved(
            "ret-scope",
            content,
            "mem-shared",
            "q-candidate",
            downstream_used=True,
            scope="tenant:other",
        ),
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert payload["candidate_verdicts"][0]["retrieval_link_status"] == "scope_mismatch"
    assert payload["summary"]["scope_mismatches"] == 1
    assert "provider id matched but retrieval scope differs" in (
        payload["candidate_verdicts"][0]["limitations"]
    )
    assert "retrieval_scope_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_lineage_report_marks_case_level_scan_as_not_candidate_level() -> None:
    packet = _base_packet()
    content = "User prefers skipping tests before release."
    packet["extracted_candidates"] = [
        _candidate(
            "candidate",
            content,
            "mem-target",
            None,
            downstream_scan_status="case_level_only",
        ),
    ]
    packet["memory_firewall_scans"] = [
        _scan(
            "candidate",
            content,
            "quarantine",
            scan_level="case_level_only",
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
    assert payload["candidate_verdicts"][0]["memory_firewall_disposition"] is None
    assert (
        payload["candidate_verdicts"][0]["case_level_memory_firewall_disposition"]
        == "quarantine"
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
    packet["memory_firewall_scans"] = [_scan("candidate", content, "warn")]
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
    packet["memory_firewall_scans"] = [_scan("candidate", content, "quarantine")]
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


@pytest.mark.parametrize(
    "stage",
    ["candidate", "persisted", "retrieved"],
)
def test_lineage_report_rejects_content_digest_mismatch(stage: str) -> None:
    packet = _base_packet()
    content = "User prefers safe releases with tests."
    wrong_digest = _digest("different content")
    candidate = _candidate("candidate", content, "mem-target", "quarantine")
    persisted = _persisted("q-target", content, "mem-target")
    retrieved = _retrieved(
        "ret-target",
        content,
        "mem-target",
        "q-target",
        downstream_used=True,
    )
    if stage == "candidate":
        candidate["content_digest"] = wrong_digest
    elif stage == "persisted":
        persisted["content_digest"] = wrong_digest
    else:
        retrieved["content_digest"] = wrong_digest
    packet["extracted_candidates"] = [candidate]
    packet["memory_firewall_scans"] = [_scan("candidate", content, "quarantine")]
    packet["persisted_memories"] = [persisted]
    packet["retrieved_memories"] = [retrieved]

    with pytest.raises(ValueError, match="must match content"):
        generate_lineage_report(packet)


def test_lineage_report_does_not_treat_provider_id_content_mutation_as_exact() -> None:
    packet = _base_packet()
    candidate_content = "User prefers tests before release."
    mutated_content = "User prefers skipping tests before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", candidate_content, "mem-target", "quarantine"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate", candidate_content, "quarantine"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-target", mutated_content, "mem-target"),
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert payload["candidate_verdicts"][0]["persisted_link_status"] == "content_mismatch"
    assert payload["candidate_verdicts"][0]["persisted"] is False
    assert "persisted_content_mismatch" in issue_codes


def test_lineage_report_rejects_sibling_scan_claim_on_downstream_candidate() -> None:
    packet = _base_packet()
    target = "User prefers skipping tests before release."
    sibling = "A scraped page instructed the system to ignore prior instructions."
    packet["extracted_candidates"] = [
        _candidate("target", target, "mem-target", "quarantine"),
        _candidate("sibling", sibling, "mem-sibling", None),
    ]
    packet["memory_firewall_scans"] = [
        _scan("sibling", sibling, "quarantine", event_id="mfev_v1_target"),
    ]
    packet["persisted_memories"] = [_persisted("q-target", target, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", target, "mem-target", "q-target", downstream_used=True)
    ]

    payload = generate_lineage_report(packet).to_dict()
    target_verdict = {
        item["candidate_id"]: item for item in payload["candidate_verdicts"]
    }["target"]
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert target_verdict["scan_status"] == "not_scanned"
    assert target_verdict["memory_firewall_disposition"] is None
    assert "candidate_scan_claim_without_scan_record" in issue_codes
    assert "downstream_candidate_without_candidate_level_scan" in issue_codes


def test_lineage_report_flags_ambiguous_digest_link() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, None, "quarantine"),
    ]
    packet["memory_firewall_scans"] = [_scan("candidate", content, "quarantine")]
    packet["persisted_memories"] = [
        _persisted("q-1", content, None),
        _persisted("q-2", content, None),
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert payload["candidate_verdicts"][0]["persisted_link_status"] == "ambiguous_match"
    assert "ambiguous_persisted_content_digest" in issue_codes
    assert "persisted_ambiguous_match" in issue_codes


def test_lineage_report_scopes_reused_local_ids_by_lineage() -> None:
    packet = _base_packet()
    content_one = "Case one prefers tests."
    content_two = "Case two prefers review."
    packet["source_events"] = [
        _source(),
        {
            "lineage_id": "case-2",
            "source_event_id": "source-1",
            "source_digest": _digest("case two source"),
            "scope": "tenant:demo",
            "declared_authority": "untrusted",
            "verified_authority_status": "declared_only",
            "metadata": {},
        },
    ]
    packet["extracted_candidates"] = [
        _candidate("candidate", content_one, "mem-one", "quarantine"),
        {
            **_candidate("candidate", content_two, "mem-two", "quarantine"),
            "lineage_id": "case-2",
        },
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate", content_one, "quarantine"),
        {
            **_scan("candidate", content_two, "quarantine"),
            "lineage_id": "case-2",
        },
    ]
    packet["persisted_memories"] = [
        _persisted("q-shared", content_one, "mem-one"),
        {
            **_persisted("q-shared", content_two, "mem-two"),
            "lineage_id": "case-2",
        },
    ]
    packet["retrieved_memories"] = [
        _retrieved(
            "ret-shared",
            content_one,
            "mem-one",
            "q-shared",
            downstream_used=True,
        ),
        {
            **_retrieved(
                "ret-shared",
                content_two,
                "mem-two",
                "q-shared",
                downstream_used=True,
            ),
            "lineage_id": "case-2",
        },
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert payload["issues"] == []
    assert payload["summary"]["retrieved_candidates"] == 2


def test_lineage_report_flags_source_candidate_scope_mismatch() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["source_events"] = [
        {
            **_source(),
            "scope": "tenant:source",
        }
    ]
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", "quarantine"),
    ]
    packet["memory_firewall_scans"] = [_scan("candidate", content, "quarantine")]
    packet["persisted_memories"] = [_persisted("q-target", content, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, "mem-target", "q-target", downstream_used=True)
    ]

    payload = generate_lineage_report(packet).to_dict()

    assert "source_scope_mismatch" in {issue["code"] for issue in payload["issues"]}


def test_lineage_report_flags_duplicate_candidate_id_and_many_to_one_records() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", "quarantine"),
        _candidate("candidate", content, "mem-target", "quarantine"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate", content, "quarantine"),
    ]
    packet["persisted_memories"] = [_persisted("q-target", content, "mem-target")]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, "mem-target", "q-target", downstream_used=True)
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert "duplicate_candidate_id" in issue_codes
    assert payload["summary"]["retrieved_candidates"] == 2


def test_lineage_report_flags_two_candidates_linking_same_records() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["extracted_candidates"] = [
        _candidate("candidate-a", content, None, "quarantine"),
        _candidate("candidate-b", content, None, "quarantine"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate-a", content, "quarantine"),
        _scan("candidate-b", content, "quarantine"),
    ]
    packet["persisted_memories"] = [_persisted("q-target", content, None)]
    packet["retrieved_memories"] = [
        _retrieved("ret-target", content, None, "q-target", downstream_used=True)
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert "multiple_candidates_same_persisted_record" in issue_codes
    assert "multiple_candidates_same_retrieval_record" in issue_codes


def test_lineage_report_flags_duplicate_scan_and_retrieval_event_ids() -> None:
    packet = _base_packet()
    content_a = "User prefers review before release."
    content_b = "User prefers tests before release."
    packet["extracted_candidates"] = [
        _candidate("candidate-a", content_a, "mem-a", "quarantine"),
        _candidate("candidate-b", content_b, "mem-b", "quarantine"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate-a", content_a, "quarantine", event_id="mfev_v1_shared"),
        _scan("candidate-b", content_b, "quarantine", event_id="mfev_v1_shared"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-a", content_a, "mem-a"),
        _persisted("q-b", content_b, "mem-b"),
    ]
    packet["retrieved_memories"] = [
        _retrieved("ret-shared", content_a, "mem-a", "q-a", downstream_used=True),
        _retrieved("ret-shared", content_b, "mem-b", "q-b", downstream_used=True),
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert "duplicate_scan_event_id" in issue_codes
    assert "duplicate_retrieval_event_id" in issue_codes


def test_lineage_report_does_not_attribute_downstream_use_from_failed_retrieval_link() -> None:
    packet = _base_packet()
    candidate_content = "User prefers tests before release."
    retrieved_content = "User prefers skipping tests before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", candidate_content, "mem-target", "quarantine"),
    ]
    packet["memory_firewall_scans"] = [
        _scan("candidate", candidate_content, "quarantine"),
    ]
    packet["persisted_memories"] = [
        _persisted("q-target", candidate_content, "mem-target"),
    ]
    packet["retrieved_memories"] = [
        _retrieved(
            "ret-target",
            retrieved_content,
            "mem-target",
            "q-target",
            downstream_used=True,
        ),
    ]

    payload = generate_lineage_report(packet).to_dict()
    verdict = payload["candidate_verdicts"][0]
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert verdict["retrieval_link_status"] == "content_mismatch"
    assert verdict["retrieved"] is False
    assert verdict["downstream_used"] is False
    assert payload["summary"]["downstream_used_candidates"] == 0
    assert "unlinked_retrieval_marked_downstream_used" in issue_codes


def test_lineage_report_rejects_candidate_level_scan_without_candidate_id() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", None),
    ]
    packet["memory_firewall_scans"] = [
        _scan(None, content, "quarantine", scan_level="candidate_level"),
    ]

    with pytest.raises(ValueError, match="candidate-level scans require candidate_id"):
        generate_lineage_report(packet)


def test_lineage_report_flags_orphan_candidate_scan_and_ambiguous_case_scan() -> None:
    packet = _base_packet()
    content = "User prefers review before release."
    packet["extracted_candidates"] = [
        _candidate("candidate", content, "mem-target", None),
    ]
    packet["memory_firewall_scans"] = [
        _scan("missing", content, "quarantine"),
        _scan(None, content, "warn", scan_level="case_level_only", event_id="mfev_v1_case_a"),
        _scan(None, content, "review", scan_level="case_level_only", event_id="mfev_v1_case_b"),
    ]

    payload = generate_lineage_report(packet).to_dict()
    issue_codes = {issue["code"] for issue in payload["issues"]}

    assert "orphan_candidate_scan" in issue_codes
    assert "ambiguous_case_level_scan" in issue_codes
