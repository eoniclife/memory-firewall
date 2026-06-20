import json

from jsonschema import Draft202012Validator

from memory_firewall import (
    POISON_DEMO_SOURCE,
    POISON_DEMO_VERSION,
    PoisonDemoResult,
    ScanEventLevel,
    demo_result_schema,
    run_poison_demo,
)


def test_poison_demo_makes_naive_overwrite_and_review_path_visible() -> None:
    result = run_poison_demo()
    payload = result.to_dict()
    outcome = payload["outcome"]

    assert isinstance(result, PoisonDemoResult)
    assert result.demo_version == POISON_DEMO_VERSION
    assert result.scan_result.source == POISON_DEMO_SOURCE
    assert outcome["source_of_record_answer"] == "Helio"
    assert outcome["naive_answer"] == "Mirage"
    assert outcome["naive_memory_was_poisoned"] is True
    assert outcome["benign_memory_passed"] is True
    assert result.scan_result.events[0].level == ScanEventLevel.PASS
    assert result.scan_result.events[1].level == ScanEventLevel.HIGH_RISK
    assert outcome["firewall_high_risk_events"] == 1
    assert outcome["queued_items"] == 1
    assert outcome["pending_preview_items"] == 0
    assert outcome["rejected_preview_items"] == 0
    assert outcome["override_preview_items"] == 1
    assert outcome["default_path_excludes_unreviewed_memory"] is True
    assert outcome["reject_path_excludes_forged_memory"] is True
    assert outcome["override_path_requires_receipt"] is True
    assert (
        payload["memory_firewall"]["override_preview"]["items"][0]["receipt"][
            "decision"
        ]
        == "allow"
    )
    Draft202012Validator(demo_result_schema()).validate(payload)


def test_poison_demo_is_deterministic() -> None:
    first = run_poison_demo().to_dict()
    second = run_poison_demo().to_dict()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
