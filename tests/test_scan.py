import json
from collections.abc import Iterator
from io import StringIO

from jsonschema import Draft202012Validator

from memory_firewall import (
    MemoryEvent,
    MemoryOperation,
    SCAN_EXIT_CLEAN,
    SCAN_EXIT_INVALID_INPUT,
    SCAN_EXIT_INTERRUPTED,
    SCAN_EXIT_REVIEW_REQUIRED,
    SCAN_VERSION,
    SourceAuthority,
    SourceType,
    TrustedStateAction,
    exit_code_for_summary,
    scan_jsonl_events,
    scan_result_schema,
    watch_stdin_events,
)


def _event(
    *,
    index: int,
    authority: SourceAuthority = SourceAuthority.SIGNED_RECORD,
    state_object: str = "Alice",
    content: str | None = None,
    subject: str | None = None,
) -> MemoryEvent:
    proposed = content or f"ERP status record {index} is active."
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
                "state_subject": subject or f"tenant:demo:finance:{index}",
                "state_predicate": "payment_recipient",
                "state_object": state_object,
            },
        }
    )


def _jsonl(*events: MemoryEvent) -> list[str]:
    return [json.dumps(event.to_dict()) + "\n" for event in events]


def test_scan_jsonl_tracks_stream_contradictions_without_trusting_state() -> None:
    trusted = _event(
        index=1,
        authority=SourceAuthority.SIGNED_RECORD,
        state_object="Alice",
        content="Signed ERP field value is Alice.",
        subject="tenant:demo:finance:payout",
    )
    untrusted = _event(
        index=2,
        authority=SourceAuthority.UNTRUSTED,
        state_object="Mallory",
        content="Untrusted note says Mallory.",
        subject="tenant:demo:finance:payout",
    )

    result = scan_jsonl_events(_jsonl(trusted, untrusted), source="events.jsonl")

    assert result.scan_version == SCAN_VERSION
    assert result.summary.total_lines == 2
    assert result.summary.analyzed_events == 2
    assert result.summary.invalid_lines == 0
    assert result.summary.high_risk_events == 1
    assert result.summary.blocked_low_authority_contradictions == 1
    assert exit_code_for_summary(result.summary) == SCAN_EXIT_REVIEW_REQUIRED
    assert result.events[1].state_analysis.trusted_state_action == (
        TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
    )
    Draft202012Validator(scan_result_schema()).validate(result.to_dict())


def test_scan_jsonl_invalid_lines_are_structured_without_raw_secret_echo() -> None:
    secret = "p@ssw0rd!"
    bad_line = json.dumps({"password": secret}) + "\n"

    result = scan_jsonl_events([bad_line], source="bad-events.jsonl")
    serialized = json.dumps(result.to_dict(), sort_keys=True)

    assert result.summary.total_lines == 1
    assert result.summary.invalid_lines == 1
    assert result.issues[0].message == "line could not be parsed as a valid MemoryEvent"
    assert secret not in serialized
    assert exit_code_for_summary(result.summary) == SCAN_EXIT_INVALID_INPUT
    Draft202012Validator(scan_result_schema()).validate(result.to_dict())


def test_scan_jsonl_untrusted_candidates_do_not_seed_future_contradictions() -> None:
    first = _event(
        index=1,
        authority=SourceAuthority.UNTRUSTED,
        state_object="Alice",
        content="Untrusted note says Alice.",
        subject="tenant:demo:finance:payout",
    )
    second = _event(
        index=2,
        authority=SourceAuthority.UNTRUSTED,
        state_object="Mallory",
        content="Untrusted note says Mallory.",
        subject="tenant:demo:finance:payout",
    )

    result = scan_jsonl_events(_jsonl(first, second), source="events.jsonl")

    assert result.summary.blocked_low_authority_contradictions == 0
    assert result.events[1].state_analysis.contradictions == ()
    assert result.events[1].state_analysis.trusted_state_action != (
        TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
    )


def test_scan_jsonl_summary_only_is_reproducible_for_1000_events() -> None:
    lines = _jsonl(*(_event(index=index) for index in range(1000)))

    first = scan_jsonl_events(lines, source="bulk.jsonl", include_events=False)
    second = scan_jsonl_events(lines, source="bulk.jsonl", include_events=False)

    assert first.summary.total_lines == 1000
    assert first.summary.analyzed_events == 1000
    assert first.events == ()
    assert first.to_dict(include_events=False) == second.to_dict(include_events=False)
    assert exit_code_for_summary(first.summary) == SCAN_EXIT_CLEAN


class _InterruptingLines:
    def __init__(self, first_line: str) -> None:
        self._first_line = first_line

    def __iter__(self) -> Iterator[str]:
        yield self._first_line
        raise KeyboardInterrupt


def test_watch_stdin_events_handles_keyboard_interrupt_cleanly() -> None:
    event = _event(index=1)
    stdout = StringIO()

    exit_code = watch_stdin_events(
        _InterruptingLines(_jsonl(event)[0]),
        stdout,
        as_json=True,
    )

    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert exit_code == SCAN_EXIT_INTERRUPTED
    assert lines[0]["record_type"] == "event"
    assert lines[-1]["record_type"] == "interrupted"
