"""Typed public models for the Memory Firewall contract."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, TypeVar

JSONScalar = str | int | float | bool | None
EVENT_ID_PREFIX = "mfev_v1_"
FINDING_ID_PREFIX = "mffind_v1_"
MAX_EVENT_ID_CHARS = 96
MAX_FINDING_ID_CHARS = 96
MAX_TEXT_FIELD_CHARS = 16_384
MAX_METADATA_ENTRIES = 64
MAX_METADATA_KEY_CHARS = 128
MAX_METADATA_STRING_CHARS = 4_096
_RFC3339_DATE_PATTERN = (
    r"(?:"
    r"(?:[1-9]\d{3})-(?:"
    r"(?:01|03|05|07|08|10|12)-(?:0[1-9]|[12]\d|3[01])|"
    r"(?:04|06|09|11)-(?:0[1-9]|[12]\d|30)|"
    r"02-(?:0[1-9]|1\d|2[0-8])"
    r")|"
    r"(?:(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|"
    r"(?:[2468][048]|[13579][26])00)-02-29)"
    r")"
)
RFC3339_TIMESTAMP_PATTERN = (
    r"^"
    + _RFC3339_DATE_PATTERN
    + r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$(?![\s\S])"
)
_RFC3339_TIMESTAMP_RE = re.compile(RFC3339_TIMESTAMP_PATTERN)

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

_EVIDENCE_SPAN_KEYS = frozenset(
    {
        "source_field",
        "start",
        "end",
        "quote",
    }
)

EnumT = TypeVar("EnumT", bound=Enum)


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
    """Risk categories frozen for the public contract."""

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


class EvidenceField(str, Enum):
    """Event fields that can anchor a finding's evidence span."""

    RAW_OR_REDACTED_CONTENT = "raw_or_redacted_content"
    PROPOSED_MEMORY = "proposed_memory"
    TIMESTAMP = "timestamp"
    SOURCE_TYPE = "source_type"
    SOURCE_ID = "source_id"
    SOURCE_AUTHORITY = "source_authority"


def _coerce_metadata(value: Mapping[str, JSONScalar]) -> dict[str, JSONScalar]:
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    metadata = dict(value)
    if len(metadata) > MAX_METADATA_ENTRIES:
        raise ValueError(f"metadata may contain at most {MAX_METADATA_ENTRIES} entries")
    for key, item in metadata.items():
        if not isinstance(key, str):
            raise TypeError("metadata keys must be strings")
        if len(key) > MAX_METADATA_KEY_CHARS:
            raise ValueError(
                f"metadata keys may contain at most {MAX_METADATA_KEY_CHARS} characters"
            )
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise TypeError(f"metadata[{key!r}] must be a JSON scalar")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError(f"metadata[{key!r}] must be a finite JSON number")
        if isinstance(item, str) and len(item) > MAX_METADATA_STRING_CHARS:
            raise ValueError(
                f"metadata[{key!r}] may contain at most "
                f"{MAX_METADATA_STRING_CHARS} characters"
            )
    return metadata


def _freeze_metadata(value: Mapping[str, JSONScalar]) -> Mapping[str, JSONScalar]:
    return MappingProxyType(_coerce_metadata(value))


def _reject_unknown_fields(
    value: Mapping[str, Any], allowed: frozenset[str], label: str
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        joined = ", ".join(extra)
        raise ValueError(f"{label} contains unknown field(s): {joined}")


def _require_string(
    value: Any, field_name: str, *, allow_empty: bool = False, max_chars: int
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > max_chars:
        raise ValueError(f"{field_name} may contain at most {max_chars} characters")
    return value


def _require_timestamp(value: Any, field_name: str = "timestamp") -> str:
    timestamp = _require_string(
        value,
        field_name,
        allow_empty=False,
        max_chars=MAX_TEXT_FIELD_CHARS,
    )
    if _RFC3339_TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp")
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")
    return timestamp


def _require_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer")
    return value


def _require_probability(value: Any, field_name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be a number")
    probability = float(value)
    if not 0 <= probability <= 1:
        raise ValueError(f"{field_name} must be between 0 and 1")
    return probability


def _coerce_enum(enum_type: type[EnumT], value: Any, field_name: str) -> EnumT:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} has unsupported value: {value}") from exc


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_memory_event_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic event id for a MemoryEvent-like payload.

    The id is derived from all canonical event fields except `event_id`, so the
    same adapter payload produces the same id across processes and Python
    versions.
    """

    payload = dict(value)
    payload["event_id"] = "_pending_event_id"
    event = MemoryEvent.from_dict(payload)
    canonical = event.to_dict()
    canonical.pop("event_id")
    digest = hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()
    return f"{EVENT_ID_PREFIX}{digest[:32]}"


def compute_memory_finding_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic id for a MemoryFinding-like payload."""

    payload = dict(value)
    payload["finding_id"] = "_pending_finding_id"
    finding = MemoryFinding.from_dict(payload)
    canonical = finding.to_dict()
    canonical.pop("finding_id")
    digest = hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()
    return f"{FINDING_ID_PREFIX}{digest[:32]}"


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    """Canonical event proposed by adapters or event proxies.

    The current contract defines the shape only. Later sprints may add readers,
    detectors, and adapters that emit this event; this model does not claim to
    scan or enforce.
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

    def __post_init__(self) -> None:
        _require_string(
            self.event_id, "event_id", allow_empty=False, max_chars=MAX_EVENT_ID_CHARS
        )
        object.__setattr__(self, "timestamp", _require_timestamp(self.timestamp))
        _require_string(
            self.actor, "actor", allow_empty=False, max_chars=MAX_TEXT_FIELD_CHARS
        )
        _require_string(
            self.user_or_tenant_scope,
            "user_or_tenant_scope",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if not isinstance(self.source_type, SourceType):
            raise TypeError("source_type must be a SourceType")
        _require_string(
            self.source_id,
            "source_id",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if not isinstance(self.source_authority, SourceAuthority):
            raise TypeError("source_authority must be a SourceAuthority")
        _require_string(
            self.raw_or_redacted_content,
            "raw_or_redacted_content",
            allow_empty=True,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.proposed_memory,
            "proposed_memory",
            allow_empty=True,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if not isinstance(self.operation, MemoryOperation):
            raise TypeError("operation must be a MemoryOperation")
        _require_string(
            self.target_namespace,
            "target_namespace",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

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

    def expected_event_id(self) -> str:
        """Return the deterministic id implied by this event's canonical fields."""

        return compute_memory_event_id(self.to_dict())

    def has_expected_event_id(self) -> bool:
        """Return whether `event_id` matches the deterministic adapter id."""

        return self.event_id == self.expected_event_id()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryEvent":
        """Build an event from a JSON-like dictionary."""

        _reject_unknown_fields(value, _EVENT_KEYS, "MemoryEvent")
        return cls(
            event_id=_require_string(
                value["event_id"],
                "event_id",
                allow_empty=False,
                max_chars=MAX_EVENT_ID_CHARS,
            ),
            timestamp=_require_timestamp(value["timestamp"]),
            actor=_require_string(
                value["actor"], "actor", allow_empty=False, max_chars=MAX_TEXT_FIELD_CHARS
            ),
            user_or_tenant_scope=_require_string(
                value["user_or_tenant_scope"],
                "user_or_tenant_scope",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            source_type=_coerce_enum(SourceType, value["source_type"], "source_type"),
            source_id=_require_string(
                value["source_id"],
                "source_id",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            source_authority=_coerce_enum(
                SourceAuthority, value["source_authority"], "source_authority"
            ),
            raw_or_redacted_content=_require_string(
                value["raw_or_redacted_content"],
                "raw_or_redacted_content",
                allow_empty=True,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            proposed_memory=_require_string(
                value["proposed_memory"],
                "proposed_memory",
                allow_empty=True,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            operation=_coerce_enum(MemoryOperation, value["operation"], "operation"),
            target_namespace=_require_string(
                value["target_namespace"],
                "target_namespace",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            metadata=_coerce_metadata(value["metadata"]),
        )

    @classmethod
    def from_adapter_payload(cls, value: Mapping[str, Any]) -> "MemoryEvent":
        """Build an event and fill `event_id` from canonical adapter material."""

        payload = dict(value)
        payload["event_id"] = compute_memory_event_id(payload)
        return cls.from_dict(payload)


@dataclass(frozen=True, slots=True)
class EvidenceSpan:
    """Structured span in a MemoryEvent field that explains a finding."""

    source_field: EvidenceField
    start: int
    end: int
    quote: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_field, EvidenceField):
            raise TypeError("source_field must be an EvidenceField")
        start = _require_int(self.start, "start")
        end = _require_int(self.end, "end")
        if start < 0:
            raise ValueError("start must be non-negative")
        if start >= MAX_TEXT_FIELD_CHARS:
            raise ValueError(f"start must be less than {MAX_TEXT_FIELD_CHARS}")
        if end > MAX_TEXT_FIELD_CHARS:
            raise ValueError(f"end must be at most {MAX_TEXT_FIELD_CHARS}")
        if end <= start:
            raise ValueError("end must be greater than start")
        quote = _require_string(
            self.quote,
            "quote",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if len(quote) != end - start:
            raise ValueError("quote length must match end - start")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable evidence span."""

        return {
            "source_field": self.source_field.value,
            "start": self.start,
            "end": self.end,
            "quote": self.quote,
        }

    def source_text(self, event: MemoryEvent) -> str:
        """Return the MemoryEvent text field referenced by this span."""

        if self.source_field == EvidenceField.RAW_OR_REDACTED_CONTENT:
            return event.raw_or_redacted_content
        if self.source_field == EvidenceField.PROPOSED_MEMORY:
            return event.proposed_memory
        if self.source_field == EvidenceField.TIMESTAMP:
            return event.timestamp
        if self.source_field == EvidenceField.SOURCE_TYPE:
            return event.source_type.value
        if self.source_field == EvidenceField.SOURCE_ID:
            return event.source_id
        if self.source_field == EvidenceField.SOURCE_AUTHORITY:
            return event.source_authority.value
        raise ValueError(f"unsupported evidence source field: {self.source_field}")

    def validate_against_event(self, event: MemoryEvent) -> None:
        """Validate that this span exactly matches the event text."""

        source = self.source_text(event)
        if self.end > len(source):
            raise ValueError("evidence span end exceeds source field length")
        if source[self.start : self.end] != self.quote:
            raise ValueError("evidence span quote does not match source field")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceSpan":
        """Build an evidence span from a JSON-like dictionary."""

        _reject_unknown_fields(value, _EVIDENCE_SPAN_KEYS, "EvidenceSpan")
        return cls(
            source_field=_coerce_enum(
                EvidenceField, value["source_field"], "source_field"
            ),
            start=_require_int(value["start"], "start"),
            end=_require_int(value["end"], "end"),
            quote=_require_string(
                value["quote"],
                "quote",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
        )


@dataclass(frozen=True, slots=True)
class MemoryFinding:
    """Explainable finding emitted by a detector in later sprints."""

    finding_id: str
    event_id: str
    risk_category: RiskCategory
    severity: RiskSeverity
    confidence: float
    evidence_span: EvidenceSpan
    detector_name: str
    detector_version: str
    explanation: str
    recommended_disposition: RecommendedDisposition
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_string(
            self.finding_id,
            "finding_id",
            allow_empty=False,
            max_chars=MAX_FINDING_ID_CHARS,
        )
        _require_string(
            self.event_id,
            "event_id",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if not isinstance(self.risk_category, RiskCategory):
            raise TypeError("risk_category must be a RiskCategory")
        if not isinstance(self.severity, RiskSeverity):
            raise TypeError("severity must be a RiskSeverity")
        object.__setattr__(
            self, "confidence", _require_probability(self.confidence, "confidence")
        )
        if not isinstance(self.evidence_span, EvidenceSpan):
            raise TypeError("evidence_span must be an EvidenceSpan")
        _require_string(
            self.detector_name,
            "detector_name",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.detector_version,
            "detector_version",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.explanation,
            "explanation",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        if not isinstance(self.recommended_disposition, RecommendedDisposition):
            raise TypeError(
                "recommended_disposition must be a RecommendedDisposition"
            )
        if isinstance(self.limitations, str) or not isinstance(self.limitations, tuple):
            raise TypeError("limitations must be a tuple of strings")
        if any(not isinstance(item, str) for item in self.limitations):
            raise TypeError("limitations must contain only strings")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return {
            "finding_id": self.finding_id,
            "event_id": self.event_id,
            "risk_category": self.risk_category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "evidence_span": self.evidence_span.to_dict(),
            "detector_name": self.detector_name,
            "detector_version": self.detector_version,
            "explanation": self.explanation,
            "recommended_disposition": self.recommended_disposition.value,
            "limitations": list(self.limitations),
        }

    def expected_finding_id(self) -> str:
        """Return the deterministic id implied by this finding's canonical fields."""

        return compute_memory_finding_id(self.to_dict())

    def has_expected_finding_id(self) -> bool:
        """Return whether `finding_id` matches the deterministic finding id."""

        return self.finding_id == self.expected_finding_id()

    def validate_against_event(self, event: MemoryEvent) -> None:
        """Validate that this finding is anchored to the supplied event."""

        if self.event_id != event.event_id:
            raise ValueError("finding event_id does not match event.event_id")
        self.evidence_span.validate_against_event(event)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryFinding":
        """Build a finding from a JSON-like dictionary."""

        raw_limitations = value["limitations"]
        limitations: tuple[str, ...]
        if (
            isinstance(raw_limitations, str)
            or isinstance(raw_limitations, Mapping)
            or not isinstance(raw_limitations, (list, tuple))
        ):
            raise TypeError("limitations must be a sequence of strings")
        limitations = tuple(raw_limitations)
        if any(not isinstance(item, str) for item in limitations):
            raise TypeError("limitations must contain only strings")
        _reject_unknown_fields(value, _FINDING_KEYS, "MemoryFinding")
        return cls(
            finding_id=_require_string(
                value["finding_id"],
                "finding_id",
                allow_empty=False,
                max_chars=MAX_FINDING_ID_CHARS,
            ),
            event_id=_require_string(
                value["event_id"],
                "event_id",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            risk_category=_coerce_enum(
                RiskCategory, value["risk_category"], "risk_category"
            ),
            severity=_coerce_enum(RiskSeverity, value["severity"], "severity"),
            confidence=_require_probability(value["confidence"], "confidence"),
            evidence_span=EvidenceSpan.from_dict(value["evidence_span"]),
            detector_name=_require_string(
                value["detector_name"],
                "detector_name",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            detector_version=_require_string(
                value["detector_version"],
                "detector_version",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            explanation=_require_string(
                value["explanation"],
                "explanation",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            recommended_disposition=_coerce_enum(
                RecommendedDisposition,
                value["recommended_disposition"],
                "recommended_disposition",
            ),
            limitations=limitations,
        )

    @classmethod
    def from_detector_payload(cls, value: Mapping[str, Any]) -> "MemoryFinding":
        """Build a finding and fill `finding_id` from canonical finding material."""

        payload = dict(value)
        payload["finding_id"] = compute_memory_finding_id(payload)
        return cls.from_dict(payload)
