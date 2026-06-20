"""Adapter conformance checks for the MF-02 contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adapters import (
    AdapterCapability,
    AdapterCapabilityReport,
    MemoryAdapter,
)
from .models import MemoryEvent


@dataclass(frozen=True, slots=True)
class ConformanceCheckResult:
    """One deterministic conformance check result."""

    name: str
    passed: bool
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable check result."""

        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ConformanceResult:
    """Complete adapter conformance result."""

    adapter_name: str
    adapter_version: str
    passed: bool
    capability_report: AdapterCapabilityReport
    checks: tuple[ConformanceCheckResult, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable conformance result."""

        return {
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "passed": self.passed,
            "capability_report": self.capability_report.to_dict(),
            "checks": [check.to_dict() for check in self.checks],
        }


def _check(name: str, passed: bool, message: str) -> ConformanceCheckResult:
    return ConformanceCheckResult(name=name, passed=passed, message=message)


def _check_capability_report_round_trip(
    report: AdapterCapabilityReport,
) -> ConformanceCheckResult:
    round_tripped = AdapterCapabilityReport.from_dict(report.to_dict())
    return _check(
        "capability_report_round_trip",
        round_tripped == report,
        "capability report round-trips through JSON-compatible dict",
    )


def _check_event_round_trip(events: tuple[MemoryEvent, ...]) -> ConformanceCheckResult:
    passed = all(MemoryEvent.from_dict(event.to_dict()) == event for event in events)
    return _check(
        "event_round_trip",
        passed,
        "all sample events round-trip through JSON-compatible dict",
    )


def _check_event_ids(events: tuple[MemoryEvent, ...]) -> ConformanceCheckResult:
    unstable = [event.event_id for event in events if not event.has_expected_event_id()]
    if unstable:
        return _check(
            "stable_event_ids",
            False,
            "sample event ids do not match deterministic event material: "
            + ", ".join(unstable),
        )
    return _check(
        "stable_event_ids",
        True,
        "sample event ids match deterministic event material",
    )


def _check_event_emission_claim(
    report: AdapterCapabilityReport, events: tuple[MemoryEvent, ...]
) -> ConformanceCheckResult:
    emits = report.supports(AdapterCapability.EMIT_MEMORY_EVENTS)
    passed = bool(events) if emits else not events
    if emits:
        message = "adapter declares event emission and provides sample events"
    else:
        message = "adapter does not declare event emission and provides no sample events"
    return _check("event_emission_capability", passed, message)


def _check_capability_exhaustiveness(
    report: AdapterCapabilityReport,
) -> ConformanceCheckResult:
    unreported = report.unreported_capabilities()
    if unreported:
        names = ", ".join(item.value for item in unreported)
        return _check(
            "capability_report_exhaustive",
            False,
            f"capability report omits known capabilities: {names}",
        )
    return _check(
        "capability_report_exhaustive",
        True,
        "capability report accounts for every known capability",
    )


def _check_enforce_report(report: AdapterCapabilityReport) -> ConformanceCheckResult:
    missing = report.missing_for_enforce_path()
    if not missing:
        return _check(
            "enforce_capability_disclosure",
            True,
            "adapter declares all enforce-relevant capabilities",
        )
    names = ", ".join(item.value for item in missing)
    return _check(
        "enforce_capability_disclosure",
        True,
        f"adapter does not claim a complete enforce path; missing: {names}",
    )


def run_adapter_conformance(adapter: MemoryAdapter) -> ConformanceResult:
    """Run deterministic conformance checks for an adapter."""

    report = adapter.capability_report
    sample_events = tuple(adapter.sample_events())
    checks = (
        _check(
            "capability_report_present",
            True,
            "adapter returned a capability report",
        ),
        _check_capability_report_round_trip(report),
        _check_capability_exhaustiveness(report),
        _check_event_emission_claim(report, sample_events),
        _check_event_round_trip(sample_events),
        _check_event_ids(sample_events),
        _check_enforce_report(report),
    )
    return ConformanceResult(
        adapter_name=report.adapter_name,
        adapter_version=report.adapter_version,
        passed=all(check.passed for check in checks),
        capability_report=report,
        checks=checks,
    )
