import json

from jsonschema import Draft202012Validator

from memory_firewall import (
    MemoryEvent,
    MemoryOperation,
    MemoryStateAssertion,
    SourceAuthority,
    SourceType,
    StateAssertionStatus,
    TrustedStateAction,
    analyze_memory_state,
    state_analysis_schema,
    state_assertion_schema,
)


def _event(
    *,
    authority: SourceAuthority,
    source_id: str,
    state_object: str,
    operation: MemoryOperation = MemoryOperation.UPSERT,
    content: str | None = None,
) -> MemoryEvent:
    proposed = content or f"Payment recipient is {state_object}."
    return MemoryEvent.from_adapter_payload(
        {
            "timestamp": "2026-06-20T15:00:00Z",
            "actor": "agent:test",
            "user_or_tenant_scope": "tenant:demo",
            "source_type": SourceType.TOOL_OUTPUT.value,
            "source_id": source_id,
            "source_authority": authority.value,
            "raw_or_redacted_content": proposed,
            "proposed_memory": proposed,
            "operation": operation.value,
            "target_namespace": "finance",
            "metadata": {
                "state_subject": "tenant:demo:finance:payout",
                "state_predicate": "payment_recipient",
                "state_object": state_object,
            },
        }
    )


def test_analyze_memory_state_emits_schema_valid_amc_candidate_mapping() -> None:
    event = _event(
        authority=SourceAuthority.TOOL_OBSERVED,
        source_id="erp:payout:123",
        state_object="Alice",
        content="ERP payout recipient is Alice.",
    )

    result = analyze_memory_state(event)

    assert result.authority_assessment.can_skip_reducer_review is False
    assert result.assertion.status == StateAssertionStatus.CANDIDATE
    assert result.amc_mapping.candidate_claim["status"] in {"candidate", "needs_review"}
    Draft202012Validator(state_assertion_schema()).validate(result.assertion.to_dict())
    Draft202012Validator(state_analysis_schema()).validate(result.to_dict())


def test_low_authority_contradiction_is_blocked_from_trusted_state() -> None:
    existing_event = _event(
        authority=SourceAuthority.SIGNED_RECORD,
        source_id="erp:payout:trusted",
        state_object="Alice",
        content="Signed ERP payout recipient is Alice.",
    )
    existing = MemoryStateAssertion.from_event(
        existing_event,
        redact_object=False,
        status=StateAssertionStatus.TRUSTED,
    )
    candidate_event = _event(
        authority=SourceAuthority.UNTRUSTED,
        source_id="unknown",
        state_object="Mallory",
        content="Payment recipient change to Mallory.",
    )

    result = analyze_memory_state(
        candidate_event,
        existing_assertions=(existing,),
    )

    assert (
        result.trusted_state_action
        == TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
    )
    assert result.contradictions
    assert "authority:low_authority_contradiction" in result.reason_codes
    assert result.amc_mapping.candidate_claim["status"] == "needs_review"
    assert result.amc_mapping.candidate_claim["metadata"]["trusted_state_action"] == (
        "blocked_low_authority_contradiction"
    )


def test_higher_authority_update_can_only_suggest_supersession_candidate() -> None:
    existing_event = _event(
        authority=SourceAuthority.USER_ASSERTED,
        source_id="msg:prior",
        state_object="Alice",
    )
    existing = MemoryStateAssertion.from_event(
        existing_event,
        redact_object=False,
        status=StateAssertionStatus.CANDIDATE,
    )
    update_event = _event(
        authority=SourceAuthority.SIGNED_RECORD,
        source_id="erp:payout:456",
        state_object="Bob",
        operation=MemoryOperation.UPDATE,
        content="Signed ERP payout recipient is Bob.",
    )

    result = analyze_memory_state(update_event, existing_assertions=(existing,))

    assert result.supersession_candidate_ids == (existing.assertion_id,)
    assert result.trusted_state_action == TrustedStateAction.REQUIRES_REDUCER_REVIEW
    assert result.amc_mapping.candidate_claim["status"] == "needs_review"


def test_sensitive_event_does_not_republish_secret_in_analysis_output() -> None:
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUV"
    event = _event(
        authority=SourceAuthority.USER_ASSERTED,
        source_id="msg:secret",
        state_object=secret,
        content=f"Remember api_key={secret}",
    )

    result = analyze_memory_state(event)
    serialized = json.dumps(result.to_dict(), sort_keys=True)

    assert result.assertion.object_redacted is True
    assert secret not in serialized
    assert result.amc_mapping.evidence_span["text_excerpt"] is None
    assert result.amc_mapping.candidate_claim["claim_text"].startswith("[redacted")


def test_analysis_result_is_deterministic_for_same_input() -> None:
    event = _event(
        authority=SourceAuthority.TOOL_OBSERVED,
        source_id="crm:account:123",
        state_object="Enterprise",
        content="CRM account tier is Enterprise.",
    )

    first = analyze_memory_state(event)
    second = analyze_memory_state(MemoryEvent.from_dict(event.to_dict()))

    assert first.to_dict() == second.to_dict()


def test_state_assertion_rejects_string_object_redacted_flag() -> None:
    event = _event(
        authority=SourceAuthority.TOOL_OBSERVED,
        source_id="crm:account:456",
        state_object="Enterprise",
        content="CRM account tier is Enterprise.",
    )
    assertion = MemoryStateAssertion.from_event(event, redact_object=False)
    payload = assertion.to_dict()
    payload["object_redacted"] = "false"

    try:
        MemoryStateAssertion.from_dict(payload)
    except TypeError as exc:
        assert "object_redacted" in str(exc)
    else:
        raise AssertionError("MemoryStateAssertion accepted string object_redacted")
