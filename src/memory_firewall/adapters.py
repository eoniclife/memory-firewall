"""Adapter capability contract for Memory Firewall."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, cast, runtime_checkable

from .models import (
    JSONScalar,
    MemoryEvent,
    MemoryOperation,
    SourceAuthority,
    SourceType,
    _coerce_metadata,
    _reject_unknown_fields,
    _require_string,
)

_REPORT_KEYS = frozenset(
    {
        "adapter_name",
        "adapter_version",
        "supported_capabilities",
        "unsupported_capabilities",
        "notes",
        "metadata",
    }
)


class AdapterCapability(str, Enum):
    """Capability vocabulary for adapter conformance reports."""

    EMIT_MEMORY_EVENTS = "emit_memory_events"
    OBSERVE_WRITES = "observe_writes"
    READ_NATIVE_MEMORY = "read_native_memory"
    WRITE_NATIVE_MEMORY = "write_native_memory"
    SUPPRESS_NATIVE_WRITES = "suppress_native_writes"
    PROVIDE_TRUSTED_CONTEXT = "provide_trusted_context"
    PERSIST_CURSOR = "persist_cursor"
    REDACT_RAW_CONTENT = "redact_raw_content"


ALL_ADAPTER_CAPABILITIES = frozenset(AdapterCapability)

ENFORCE_RELEVANT_CAPABILITIES = frozenset(
    {
        AdapterCapability.EMIT_MEMORY_EVENTS,
        AdapterCapability.OBSERVE_WRITES,
        AdapterCapability.SUPPRESS_NATIVE_WRITES,
        AdapterCapability.PROVIDE_TRUSTED_CONTEXT,
    }
)


def _coerce_capabilities(
    value: Iterable[AdapterCapability | str], field_name: str
) -> frozenset[AdapterCapability]:
    if isinstance(value, str):
        raise TypeError(f"{field_name} must be a sequence of capability strings")
    capabilities: set[AdapterCapability] = set()
    for item in value:
        if isinstance(item, AdapterCapability):
            capabilities.add(item)
        elif isinstance(item, str):
            capabilities.add(AdapterCapability(item))
        else:
            raise TypeError(f"{field_name} must contain capability strings")
    return frozenset(capabilities)


def _coerce_notes(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        raise TypeError("notes must be a sequence of strings")
    notes = tuple(value)
    if any(not isinstance(item, str) for item in notes):
        raise TypeError("notes must contain only strings")
    for note in notes:
        _require_string(note, "notes item", allow_empty=False, max_chars=2_048)
    return notes


@dataclass(frozen=True, slots=True)
class AdapterCapabilityReport:
    """Machine-readable adapter capability report.

    This describes what an adapter can expose. It does not by itself mean a
    real framework adapter exists or that enforce mode is implemented.
    """

    adapter_name: str
    adapter_version: str
    supported_capabilities: Iterable[AdapterCapability | str]
    unsupported_capabilities: Iterable[AdapterCapability | str] = field(
        default_factory=tuple
    )
    notes: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_string(
            self.adapter_name,
            "adapter_name",
            allow_empty=False,
            max_chars=256,
        )
        _require_string(
            self.adapter_version,
            "adapter_version",
            allow_empty=False,
            max_chars=128,
        )
        supported = _coerce_capabilities(
            self.supported_capabilities, "supported_capabilities"
        )
        unsupported = _coerce_capabilities(
            self.unsupported_capabilities, "unsupported_capabilities"
        )
        overlap = supported & unsupported
        if overlap:
            names = ", ".join(sorted(item.value for item in overlap))
            raise ValueError(f"capabilities cannot be both supported and unsupported: {names}")
        object.__setattr__(self, "supported_capabilities", supported)
        object.__setattr__(self, "unsupported_capabilities", unsupported)
        object.__setattr__(self, "notes", _coerce_notes(self.notes))
        object.__setattr__(self, "metadata", _coerce_metadata(self.metadata))

    def supports(self, capability: AdapterCapability) -> bool:
        """Return whether this report declares a capability as supported."""

        supported = cast(frozenset[AdapterCapability], self.supported_capabilities)
        return capability in supported

    def missing_for_enforce_path(self) -> tuple[AdapterCapability, ...]:
        """Return enforce-relevant capabilities not declared as supported."""

        supported = cast(frozenset[AdapterCapability], self.supported_capabilities)
        missing = ENFORCE_RELEVANT_CAPABILITIES - supported
        return tuple(sorted(missing, key=lambda item: item.value))

    def unreported_capabilities(self) -> tuple[AdapterCapability, ...]:
        """Return capabilities omitted from supported and unsupported lists."""

        supported = cast(frozenset[AdapterCapability], self.supported_capabilities)
        unsupported = cast(frozenset[AdapterCapability], self.unsupported_capabilities)
        unreported = ALL_ADAPTER_CAPABILITIES - supported - unsupported
        return tuple(sorted(unreported, key=lambda item: item.value))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable capability report."""

        return {
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "supported_capabilities": sorted(
                item.value
                for item in cast(
                    frozenset[AdapterCapability], self.supported_capabilities
                )
            ),
            "unsupported_capabilities": sorted(
                item.value
                for item in cast(
                    frozenset[AdapterCapability], self.unsupported_capabilities
                )
            ),
            "notes": list(self.notes),
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdapterCapabilityReport":
        """Build a capability report from a JSON-like dictionary."""

        _reject_unknown_fields(value, _REPORT_KEYS, "AdapterCapabilityReport")
        return cls(
            adapter_name=_require_string(
                value["adapter_name"],
                "adapter_name",
                allow_empty=False,
                max_chars=256,
            ),
            adapter_version=_require_string(
                value["adapter_version"],
                "adapter_version",
                allow_empty=False,
                max_chars=128,
            ),
            supported_capabilities=value["supported_capabilities"],
            unsupported_capabilities=value["unsupported_capabilities"],
            notes=value["notes"],
            metadata=_coerce_metadata(value["metadata"]),
        )


@runtime_checkable
class MemoryAdapter(Protocol):
    """Protocol implemented by adapters that want MF-02 conformance checks."""

    @property
    def capability_report(self) -> AdapterCapabilityReport:
        """Return a stable machine-readable capability report."""
        ...

    def sample_events(self) -> Sequence[MemoryEvent]:
        """Return deterministic sample events for adapter conformance."""
        ...


@dataclass(frozen=True, slots=True)
class DemoMemoryAdapter:
    """Built-in fake adapter used only to prove the MF-02 contract."""

    @property
    def capability_report(self) -> AdapterCapabilityReport:
        """Return the fake adapter's capability report."""

        return AdapterCapabilityReport(
            adapter_name="memory-firewall-demo",
            adapter_version="0.1.0.dev2",
            supported_capabilities=(
                AdapterCapability.EMIT_MEMORY_EVENTS,
                AdapterCapability.OBSERVE_WRITES,
                AdapterCapability.REDACT_RAW_CONTENT,
            ),
            unsupported_capabilities=(
                AdapterCapability.READ_NATIVE_MEMORY,
                AdapterCapability.WRITE_NATIVE_MEMORY,
                AdapterCapability.SUPPRESS_NATIVE_WRITES,
                AdapterCapability.PROVIDE_TRUSTED_CONTEXT,
                AdapterCapability.PERSIST_CURSOR,
            ),
            notes=(
                "Fake adapter for MF-02 conformance only; no framework "
                "integration or enforce path is implemented.",
            ),
            metadata={"demo": True},
        )

    def sample_events(self) -> Sequence[MemoryEvent]:
        """Return deterministic fake events for conformance tests."""

        return (
            MemoryEvent.from_adapter_payload(
                {
                    "timestamp": "2026-06-20T14:00:00Z",
                    "actor": "agent:demo",
                    "user_or_tenant_scope": "tenant:demo",
                    "source_type": SourceType.USER_MESSAGE.value,
                    "source_id": "msg_demo_001",
                    "source_authority": SourceAuthority.USER_ASSERTED.value,
                    "raw_or_redacted_content": "Remember that approvals go to Alice.",
                    "proposed_memory": "Approvals go to Alice.",
                    "operation": MemoryOperation.CREATE.value,
                    "target_namespace": "demo",
                    "metadata": {"redacted": False, "trace_id": "trace_demo_001"},
                }
            ),
        )


def demo_memory_adapter() -> MemoryAdapter:
    """Return the built-in fake adapter for local conformance smoke tests."""

    return DemoMemoryAdapter()
