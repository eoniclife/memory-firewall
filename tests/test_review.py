import json

import pytest
from jsonschema import Draft202012Validator

from memory_firewall import (
    MemoryEvent,
    MemoryOperation,
    OverrideDecision,
    ReviewItemStatus,
    ScanResult,
    SourceAuthority,
    SourceType,
    allow_review_item,
    enqueue_scan_result,
    override_receipt_schema,
    reject_review_item,
    review_queue_schema,
    scan_jsonl_events,
    trusted_read_preview,
    trusted_read_preview_schema,
)


def _event(
    *,
    index: int,
    authority: SourceAuthority = SourceAuthority.SIGNED_RECORD,
    state_object: str = "Alice",
    content: str | None = None,
    subject: str = "tenant:demo:finance:payout",
) -> MemoryEvent:
    proposed = content or f"ERP payout record {index} says {state_object}."
    return MemoryEvent.from_adapter_payload(
        {
            "timestamp": "2026-06-20T15:00:00Z",
            "actor": "agent:test",
            "user_or_tenant_scope": "tenant:demo",
            "source_type": SourceType.TOOL_OUTPUT.value,
            "source_id": f"erp:record:{index}",
            "source_authority": authority.value,
            "raw_or_redacted_content": proposed,
            "proposed_memory": proposed,
            "operation": MemoryOperation.UPSERT.value,
            "target_namespace": "finance",
            "metadata": {
                "state_subject": subject,
                "state_predicate": "payment_recipient",
                "state_object": state_object,
            },
        }
    )


def _jsonl(*events: MemoryEvent) -> list[str]:
    return [json.dumps(event.to_dict()) + "\n" for event in events]


def _contradiction_scan() -> ScanResult:
    trusted = _event(
        index=1,
        authority=SourceAuthority.SIGNED_RECORD,
        state_object="Alice",
    )
    untrusted = _event(
        index=2,
        authority=SourceAuthority.UNTRUSTED,
        state_object="Mallory",
    )
    return scan_jsonl_events(_jsonl(trusted, untrusted), source="events.jsonl")


def test_enqueue_scan_result_adds_only_high_risk_events() -> None:
    result = _contradiction_scan()

    queue = enqueue_scan_result(result)

    assert len(queue.items) == 1
    assert queue.items[0].line_number == 2
    assert queue.items[0].status == ReviewItemStatus.PENDING
    assert queue.items[0].receipt_id is None
    assert queue.items[0].event_id == result.events[1].event_id
    assert queue.items[0].assertion.object_value == "Mallory"
    Draft202012Validator(review_queue_schema()).validate(queue.to_dict())


def test_allow_review_item_emits_receipt_and_trusted_read_preview() -> None:
    queue = enqueue_scan_result(_contradiction_scan())
    item_id = queue.items[0].item_id

    allowed = allow_review_item(
        queue,
        item_id,
        reason="verified against the ERP export",
        reviewer="aditya",
    )
    receipt = allowed.receipts[0]
    preview = trusted_read_preview(allowed)

    assert allowed.items[0].status == ReviewItemStatus.ALLOWED
    assert receipt.decision == OverrideDecision.ALLOW
    assert allowed.items[0].receipt_id == receipt.receipt_id
    assert len(preview.items) == 1
    assert preview.items[0].item_id == item_id
    assert preview.items[0].assertion.object_value == "Mallory"
    assert preview.metadata is not None
    assert preview.metadata["trusted_ledger_write"] is False
    Draft202012Validator(override_receipt_schema()).validate(receipt.to_dict())
    Draft202012Validator(trusted_read_preview_schema()).validate(preview.to_dict())


def test_reject_review_item_excludes_item_from_trusted_read_preview() -> None:
    queue = enqueue_scan_result(_contradiction_scan())
    item_id = queue.items[0].item_id

    rejected = reject_review_item(
        queue,
        item_id,
        reason="does not match the signed source of record",
        reviewer="aditya",
    )
    preview = trusted_read_preview(rejected)

    assert rejected.items[0].status == ReviewItemStatus.REJECTED
    assert rejected.receipts[0].decision == OverrideDecision.REJECT
    assert preview.items == ()
    serialized = json.dumps(preview.to_dict(), sort_keys=True)
    assert item_id not in serialized


def test_repeated_same_decision_is_idempotent_and_conflict_is_rejected() -> None:
    queue = enqueue_scan_result(_contradiction_scan())
    item_id = queue.items[0].item_id

    allowed = allow_review_item(
        queue,
        item_id,
        reason="verified locally",
        reviewer="aditya",
    )
    again = allow_review_item(
        allowed,
        item_id,
        reason="verified locally",
        reviewer="aditya",
    )

    assert again.to_dict() == allowed.to_dict()
    with pytest.raises(ValueError, match="already decided"):
        reject_review_item(
            allowed,
            item_id,
            reason="changed my mind",
            reviewer="aditya",
        )


def test_allow_and_queue_receipts_redact_secret_like_values() -> None:
    secret = "p@ssw0rd!"
    event = _event(
        index=1,
        authority=SourceAuthority.UNTRUSTED,
        state_object=f"password={secret}",
        content=f"The database password is {secret}.",
        subject="tenant:demo:secrets:db",
    )
    scan = scan_jsonl_events(_jsonl(event), source="secrets.jsonl")
    queue = enqueue_scan_result(scan)

    allowed = allow_review_item(
        queue,
        queue.items[0].item_id,
        reason=f"temporary exception because password={secret}",
        reviewer="aditya",
    )
    serialized_queue = json.dumps(allowed.to_dict(), sort_keys=True)
    serialized_preview = json.dumps(trusted_read_preview(allowed).to_dict(), sort_keys=True)

    assert secret not in serialized_queue
    assert secret not in serialized_preview
    assert "[redacted-secret]" in serialized_queue
