"""Typed public models for the MF-01 Memory Firewall contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

JSONScalar = str | int | float | bool | None

_EVENT_KEYS = frozenset(
    {
        "event_id",
        "timestamp",
        "actor",
        "user_or_tenant_scope",
        "source_type",
        "source_id",
        "source_authority",
        "raw_or_redacted_content",
        "proposed_memory",
        "operation",
        "target_namespace",
        "metadata",
    }
)

_FINDING_KEYS = frozenset(
    {
        "finding_id",
        "event_id",
        "risk_category",
        "severity",
        "confidence",
        "evidence_span",
        "detector_name",
        "detector_version",
        "explanation",
        "recommended_disposition",
        "limitations",
    }
)


class SourceType(str, Enum):
    """Where a proposed memory came from."""

    USER_MESSAGE = "user_message"
    AGENT_OUTPUT = "agent_output"
    TOOL_OUTPUT = "tool_output"
    FILE = "file"
    WEB_PAGE = "web_page"
    API = "api"
    SYSTEM_PROMPT = "system_prompt"
    MEMORY_IMPORT = "memory_import"
    UNKNOWN = "unknown"


class SourceAuthority(str, Enum):
    """How much authority the source can carry before review."""

    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"
    USER_ASSERTED = "user_asserted"
    TOOL_OBSERVED = "tool_observed"
    SYSTEM = "system"
    SIGNED_RECORD = "signed_record"
    HUMAN_APPROVED = "human_approved"


class MemoryOperation(str, Enum):
    """The requested operation against memory."""

    CREATE = "create"
    UPDATE = "update"
    UPSERT = "upsert"
    DELETE = "delete"
    IMPORT = "import"


class RiskCategory(str, Enum):
    """Risk categories frozen by MF-01."""

    PROVENANCE_GAP = "provenance_gap"
    INSTRUCTION_INJECTION = "instruction_injection"
    AUTHORITY_OR_IDENTITY_CHANGE = "authority_or_identity_change"
    CONTRADICTION = "contradiction"
    TEMPORAL_OR_STALE_STATE = "temporal_or_stale_state"
    SCOPE_OR_PRIVACY_VIOLATION = "scope_or_privacy_violation"
    PROCEDURAL_POISONING = "procedural_poisoning"
    ANOMALOUS_PERSISTENCE = "anomalous_persistence"


class RiskSeverity(str, Enum):
    """Finding severity vocabulary."""

    INFORMATIONAL = "informational"
    SUSPICIOUS = "suspicious"
    HIGH_IMPACT = "high_impact"


class RecommendedDisposition(str, Enum):
    """Inspectable policy outcome vocabulary."""

    PASS = "pass"
    WARN = "warn"
    REVIEW = "review"
    QUARANTINE = "quarantine"


def _coerce_metadata(value: Mapping[str, JSONScalar] | None) -> dict[str, JSONScalar]:
    metadata = dict(value or {})
    for key, item in metadata.items():
        if not isinstance(key, str):
            raise TypeError("metadata keys must be strings")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise TypeError(f"metadata[{key!r}] must be a JSON scalar")
    return metadata


def _reject_unknown_fields(
    value: Mapping[str, Any], allowed: frozenset[str], label: str
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        joined = ", ".join(extra)
        raise ValueError(f"{label} contains unknown field(s): {joined}")


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    """Canonical event proposed by adapters or event proxies.

    MF-01 defines the shape only. Later sprints may add readers, detectors, and
    adapters that emit this event; this model does not claim to scan or enforce.
    """

    event_id: str
    timestamp: str
    actor: str
    user_or_tenant_scope: str
    source_type: SourceType
    source_id: str
    source_authority: SourceAuthority
    raw_or_redacted_content: str
    proposed_memory: str
    operation: MemoryOperation
    target_namespace: str
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "user_or_tenant_scope": self.user_or_tenant_scope,
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "source_authority": self.source_authority.value,
            "raw_or_redacted_content": self.raw_or_redacted_content,
            "proposed_memory": self.proposed_memory,
            "operation": self.operation.value,
            "target_namespace": self.target_namespace,
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryEvent":
        """Build an event from a JSON-like dictionary."""

        _reject_unknown_fields(value, _EVENT_KEYS, "MemoryEvent")
        return cls(
            event_id=str(value["event_id"]),
            timestamp=str(value["timestamp"]),
            actor=str(value["actor"]),
            user_or_tenant_scope=str(value["user_or_tenant_scope"]),
            source_type=SourceType(str(value["source_type"])),
            source_id=str(value["source_id"]),
            source_authority=SourceAuthority(str(value["source_authority"])),
            raw_or_redacted_content=str(value["raw_or_redacted_content"]),
            proposed_memory=str(value["proposed_memory"]),
            operation=MemoryOperation(str(value["operation"])),
            target_namespace=str(value["target_namespace"]),
            metadata=_coerce_metadata(value["metadata"]),
        )


@dataclass(frozen=True, slots=True)
class MemoryFinding:
    """Explainable finding emitted by a detector in later sprints."""

    finding_id: str
    event_id: str
    risk_category: RiskCategory
    severity: RiskSeverity
    confidence: float
    evidence_span: str
    detector_name: str
    detector_version: str
    explanation: str
    recommended_disposition: RecommendedDisposition
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return {
            "finding_id": self.finding_id,
            "event_id": self.event_id,
            "risk_category": self.risk_category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "evidence_span": self.evidence_span,
            "detector_name": self.detector_name,
            "detector_version": self.detector_version,
            "explanation": self.explanation,
            "recommended_disposition": self.recommended_disposition.value,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryFinding":
        """Build a finding from a JSON-like dictionary."""

        raw_limitations = value["limitations"]
        limitations: tuple[str, ...]
        if isinstance(raw_limitations, str):
            raise TypeError("limitations must be a sequence of strings")
        else:
            limitations = tuple(raw_limitations)
        if any(not isinstance(item, str) for item in limitations):
            raise TypeError("limitations must contain only strings")
        _reject_unknown_fields(value, _FINDING_KEYS, "MemoryFinding")
        return cls(
            finding_id=str(value["finding_id"]),
            event_id=str(value["event_id"]),
            risk_category=RiskCategory(str(value["risk_category"])),
            severity=RiskSeverity(str(value["severity"])),
            confidence=float(value["confidence"]),
            evidence_span=str(value["evidence_span"]),
            detector_name=str(value["detector_name"]),
            detector_version=str(value["detector_version"]),
            explanation=str(value["explanation"]),
            recommended_disposition=RecommendedDisposition(
                str(value["recommended_disposition"])
            ),
            limitations=limitations,
        )
