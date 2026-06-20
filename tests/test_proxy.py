from collections.abc import Sequence

import pytest
from jsonschema import Draft202012Validator

from memory_firewall import (
    AdapterCapability,
    AdapterCapabilityReport,
    MemoryEvent,
    MemoryOperation,
    ProxyMode,
    REFERENCE_PROXY_SOURCE,
    REFERENCE_PROXY_VERSION,
    ReferenceProxyResult,
    ScanEventLevel,
    SourceAuthority,
    SourceType,
    reference_proxy_capability_report,
    reference_proxy_result_schema,
    run_adapter_conformance,
    run_reference_proxy,
)


def test_reference_proxy_capability_report_declares_enforce_path() -> None:
    report = reference_proxy_capability_report()
    supported = set(report.to_dict()["supported_capabilities"])

    assert report.adapter_name == "memory-firewall-reference-sqlite"
    assert report.missing_for_enforce_path() == ()
    assert AdapterCapability.SUPPRESS_NATIVE_WRITES.value in supported
    assert report.metadata["context_channel"] == "governed_context_preview"
    assert report.metadata["production_adapter"] is False
    assert any("preview only" in note for note in report.notes)


def test_reference_proxy_modes_show_observe_overlay_enforce_semantics() -> None:
    observe = run_reference_proxy(ProxyMode.OBSERVE)
    overlay = run_reference_proxy(ProxyMode.OVERLAY)
    enforce = run_reference_proxy(ProxyMode.ENFORCE)

    assert isinstance(enforce, ReferenceProxyResult)
    assert observe.proxy_version == REFERENCE_PROXY_VERSION
    assert observe.scan_result.source == REFERENCE_PROXY_SOURCE
    assert observe.outcome()["native_answer"] == "Mirage"
    assert observe.outcome()["governed_context_answer"] is None
    assert observe.outcome()["suppressed_native_event_ids"] == []
    assert overlay.outcome()["native_answer"] == "Mirage"
    assert overlay.outcome()["governed_context_answer"] == "Helio"
    assert overlay.outcome()["suppressed_native_event_ids"] == []
    assert enforce.outcome()["native_answer"] == "Helio"
    assert enforce.outcome()["governed_context_answer"] == "Helio"
    assert len(enforce.outcome()["suppressed_native_event_ids"]) == 1
    assert enforce.scan_result.events[0].level == ScanEventLevel.PASS
    assert enforce.scan_result.events[1].level == ScanEventLevel.HIGH_RISK
    assert enforce.write_decisions[1].native_write is False
    assert enforce.write_decisions[1].review_item_id == enforce.review_queue.items[0].item_id
    assert enforce.trusted_read_preview.items == ()
    Draft202012Validator(reference_proxy_result_schema()).validate(enforce.to_dict())


def test_reference_proxy_output_is_deterministic() -> None:
    first = run_reference_proxy(ProxyMode.ENFORCE).to_dict()
    second = run_reference_proxy(ProxyMode.ENFORCE).to_dict()

    assert first == second


def test_reference_proxy_rejects_scan_incompatible_custom_events() -> None:
    custom_event = MemoryEvent(
        event_id="evt_custom_valid_runtime",
        timestamp="2026-06-20T15:02:00Z",
        actor="agent:reference-proxy",
        user_or_tenant_scope="tenant:demo",
        source_type=SourceType.TOOL_OUTPUT,
        source_id="registry:project:custom-record",
        source_authority=SourceAuthority.SIGNED_RECORD,
        raw_or_redacted_content="Signed project registry record says Helio.",
        proposed_memory="Signed project registry record says Helio.",
        operation=MemoryOperation.UPSERT,
        target_namespace="project",
        metadata={
            "state_subject": "tenant:demo:project:codename",
            "state_predicate": "project_codename",
            "state_object": "Helio",
        },
    )

    with pytest.raises(ValueError, match="scan-compatible MemoryEvent records"):
        run_reference_proxy(ProxyMode.OVERLAY, events=(custom_event,))


def test_reference_proxy_capability_report_passes_conformance() -> None:
    class ReferenceProxyAdapter:
        @property
        def capability_report(self) -> AdapterCapabilityReport:
            return reference_proxy_capability_report()

        def sample_events(self) -> Sequence[MemoryEvent]:
            from memory_firewall import reference_proxy_demo_events

            return reference_proxy_demo_events()

    result = run_adapter_conformance(ReferenceProxyAdapter())

    assert result.passed
