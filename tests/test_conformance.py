from dataclasses import replace

from memory_firewall import (
    AdapterCapability,
    AdapterCapabilityReport,
    MemoryEvent,
    MemoryAdapter,
    demo_memory_adapter,
    run_adapter_conformance,
)


class UnstableIdAdapter:
    @property
    def capability_report(self) -> AdapterCapabilityReport:
        return AdapterCapabilityReport(
            adapter_name="unstable",
            adapter_version="0.0.1",
            supported_capabilities=(AdapterCapability.EMIT_MEMORY_EVENTS,),
            unsupported_capabilities=(
                AdapterCapability.OBSERVE_WRITES,
                AdapterCapability.READ_NATIVE_MEMORY,
                AdapterCapability.WRITE_NATIVE_MEMORY,
                AdapterCapability.SUPPRESS_NATIVE_WRITES,
                AdapterCapability.PROVIDE_TRUSTED_CONTEXT,
                AdapterCapability.PERSIST_CURSOR,
                AdapterCapability.REDACT_RAW_CONTENT,
            ),
            notes=("intentionally broken",),
            metadata={},
        )

    def sample_events(self) -> tuple[MemoryEvent, ...]:
        event = demo_memory_adapter().sample_events()[0]
        return (replace(event, event_id="evt_not_canonical"),)


def test_demo_adapter_passes_conformance() -> None:
    result = run_adapter_conformance(demo_memory_adapter())
    checks = {check.name: check.passed for check in result.checks}

    assert result.passed
    assert checks["capability_report_round_trip"]
    assert checks["stable_event_ids"]
    assert result.capability_report.adapter_name == "memory-firewall-demo"


def test_conformance_detects_unstable_event_ids() -> None:
    result = run_adapter_conformance(UnstableIdAdapter())
    checks = {check.name: check for check in result.checks}

    assert isinstance(UnstableIdAdapter(), MemoryAdapter)
    assert not result.passed
    assert not checks["stable_event_ids"].passed
    assert "deterministic event material" in checks["stable_event_ids"].message


def test_conformance_detects_incomplete_capability_reports() -> None:
    class IncompleteReportAdapter(UnstableIdAdapter):
        @property
        def capability_report(self) -> AdapterCapabilityReport:
            return AdapterCapabilityReport(
                adapter_name="incomplete",
                adapter_version="0.0.1",
                supported_capabilities=(AdapterCapability.EMIT_MEMORY_EVENTS,),
                unsupported_capabilities=(),
                notes=("intentionally incomplete",),
                metadata={},
            )

    result = run_adapter_conformance(IncompleteReportAdapter())
    checks = {check.name: check for check in result.checks}

    assert not result.passed
    assert not checks["capability_report_exhaustive"].passed
    assert "omits known capabilities" in checks["capability_report_exhaustive"].message
