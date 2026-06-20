from memory_firewall import (
    AdapterCapability,
    AdapterCapabilityReport,
    demo_memory_adapter,
)


def test_adapter_capability_report_round_trips_to_dict() -> None:
    report = AdapterCapabilityReport(
        adapter_name="fake",
        adapter_version="0.0.1",
        supported_capabilities=(
            AdapterCapability.EMIT_MEMORY_EVENTS,
            "observe_writes",
        ),
        unsupported_capabilities=(AdapterCapability.SUPPRESS_NATIVE_WRITES,),
        notes=("fake report",),
        metadata={"demo": True},
    )

    payload = report.to_dict()

    assert payload["supported_capabilities"] == [
        "emit_memory_events",
        "observe_writes",
    ]
    assert AdapterCapabilityReport.from_dict(payload) == report


def test_adapter_capability_report_rejects_overlap() -> None:
    try:
        AdapterCapabilityReport(
            adapter_name="fake",
            adapter_version="0.0.1",
            supported_capabilities=(AdapterCapability.EMIT_MEMORY_EVENTS,),
            unsupported_capabilities=(AdapterCapability.EMIT_MEMORY_EVENTS,),
            notes=(),
            metadata={},
        )
    except ValueError as exc:
        assert "both supported and unsupported" in str(exc)
    else:
        raise AssertionError("AdapterCapabilityReport accepted overlap")


def test_demo_adapter_discloses_no_enforce_path() -> None:
    report = demo_memory_adapter().capability_report
    missing = {item.value for item in report.missing_for_enforce_path()}

    assert report.supports(AdapterCapability.EMIT_MEMORY_EVENTS)
    assert report.unreported_capabilities() == ()
    assert "suppress_native_writes" in missing
    assert "provide_trusted_context" in missing
