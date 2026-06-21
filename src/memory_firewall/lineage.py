"""Stage-aware candidate lineage reports for memory evidence packets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .models import (
    JSONScalar,
    RecommendedDisposition,
    SourceAuthority,
    _coerce_enum,
    _coerce_metadata,
    _require_string,
)
from .policy import max_disposition

LINEAGE_VERSION = "mf-27"
CONTENT_DIGEST_PREFIX = "sha256:"
LINEAGE_MAX_TEXT_CHARS = 16_384

_SOURCE_KEYS = frozenset(
    {
        "lineage_id",
        "source_event_id",
        "source_digest",
        "scope",
        "declared_authority",
        "verified_authority_status",
        "metadata",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "lineage_id",
        "candidate_id",
        "source_event_id",
        "content",
        "content_digest",
        "provider_memory_id",
        "scope",
        "declared_authority",
        "verified_authority_status",
        "memory_firewall_event_id",
        "memory_firewall_disposition",
        "memory_firewall_finding_count",
        "metadata",
    }
)
_SCAN_KEYS = frozenset(
    {
        "lineage_id",
        "memory_firewall_event_id",
        "candidate_id",
        "scan_level",
        "scanned_content",
        "scanned_content_digest",
        "scanned_scope",
        "detector_pack_version",
        "policy_version",
        "disposition",
        "finding_count",
        "metadata",
    }
)
_PERSISTED_KEYS = frozenset(
    {
        "lineage_id",
        "persisted_record_id",
        "provider_memory_id",
        "content",
        "content_digest",
        "scope",
        "metadata",
    }
)
_RETRIEVED_KEYS = frozenset(
    {
        "lineage_id",
        "retrieval_event_id",
        "provider_memory_id",
        "persisted_record_id",
        "content",
        "content_digest",
        "scope",
        "downstream_used",
        "metadata",
    }
)
_REPORT_KEYS = frozenset(
    {
        "lineage_version",
        "provider",
        "provider_version",
        "source_events",
        "extracted_candidates",
        "memory_firewall_scans",
        "persisted_memories",
        "retrieved_memories",
        "metadata",
    }
)


class LineageLinkStatus(str, Enum):
    """How confidently a candidate was linked across provider stages."""

    EXACT_PROVIDER_ID_AND_DIGEST = "exact_provider_id_and_digest"
    EXACT_PERSISTED_ID_AND_DIGEST = "exact_persisted_id_and_digest"
    UNIQUE_CONTENT_DIGEST = "unique_content_digest"
    NOT_LINKED = "not_linked"
    SCOPE_MISMATCH = "scope_mismatch"
    CONTENT_MISMATCH = "content_mismatch"
    AMBIGUOUS_MATCH = "ambiguous_match"
    CHAIN_INCONSISTENT = "chain_inconsistent"


class CandidateScanStatus(str, Enum):
    """Whether Memory Firewall has a candidate-level scan verdict."""

    CANDIDATE_LEVEL = "candidate_level"
    CASE_LEVEL_ONLY = "case_level_only"
    NOT_SCANNED = "not_scanned"


class MemoryFirewallScanLevel(str, Enum):
    CANDIDATE_LEVEL = "candidate_level"
    CASE_LEVEL_ONLY = "case_level_only"


def _reject_unknown_fields(
    value: Mapping[str, Any], allowed: frozenset[str], label: str
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise ValueError(f"{label} contains unknown field(s): {', '.join(extra)}")


def _optional_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_string(
        value,
        field_name,
        allow_empty=False,
        max_chars=LINEAGE_MAX_TEXT_CHARS,
    )


def _require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a boolean")
    return value


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


def _require_tuple(value: tuple[Any, ...], field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, tuple):
        raise TypeError(f"{field_name} must be a tuple")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return tuple(value)


def _digest_content(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{CONTENT_DIGEST_PREFIX}{digest}"


def _normalize_digest(
    content: str | None,
    content_digest: str | None,
    field_name: str,
) -> str:
    if content_digest is not None:
        digest = _require_string(
            content_digest,
            field_name,
            allow_empty=False,
            max_chars=80,
        )
        if not digest.startswith(CONTENT_DIGEST_PREFIX):
            raise ValueError(f"{field_name} must start with {CONTENT_DIGEST_PREFIX}")
        if len(digest) != len(CONTENT_DIGEST_PREFIX) + 64:
            raise ValueError(f"{field_name} must contain a sha256 hex digest")
        try:
            int(digest[len(CONTENT_DIGEST_PREFIX) :], 16)
        except ValueError as exc:
            raise ValueError(f"{field_name} must contain a sha256 hex digest") from exc
        if content is not None and _digest_content(content) != digest:
            raise ValueError(f"{field_name} must match content")
        return digest
    if content is None:
        raise ValueError(f"{field_name} requires content or content_digest")
    return _digest_content(content)


def _highest_disposition(
    items: tuple["CandidateLineageVerdict", ...],
) -> RecommendedDisposition:
    disposition = RecommendedDisposition.PASS
    for item in items:
        if item.memory_firewall_disposition is not None:
            disposition = max_disposition(disposition, item.memory_firewall_disposition)
    return disposition


@dataclass(frozen=True, slots=True)
class ObservedSourceRecord:
    """Source-stage record supplied by a validation packet or adapter."""

    lineage_id: str
    source_event_id: str
    source_digest: str
    scope: str
    declared_authority: SourceAuthority
    verified_authority_status: str
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_string(
            self.lineage_id,
            "lineage_id",
            allow_empty=False,
            max_chars=LINEAGE_MAX_TEXT_CHARS,
        )
        _require_string(
            self.source_event_id,
            "source_event_id",
            allow_empty=False,
            max_chars=LINEAGE_MAX_TEXT_CHARS,
        )
        _normalize_digest(None, self.source_digest, "source_digest")
        _require_string(
            self.scope,
            "scope",
            allow_empty=False,
            max_chars=LINEAGE_MAX_TEXT_CHARS,
        )
        if not isinstance(self.declared_authority, SourceAuthority):
            raise TypeError("declared_authority must be a SourceAuthority")
        _require_string(
            self.verified_authority_status,
            "verified_authority_status",
            allow_empty=False,
            max_chars=128,
        )
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable source record."""

        return {
            "lineage_id": self.lineage_id,
            "source_event_id": self.source_event_id,
            "source_digest": self.source_digest,
            "scope": self.scope,
            "declared_authority": self.declared_authority.value,
            "verified_authority_status": self.verified_authority_status,
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservedSourceRecord":
        """Build a source record from a JSON-like mapping."""

        _reject_unknown_fields(value, _SOURCE_KEYS, "ObservedSourceRecord")
        return cls(
            lineage_id=_require_string(
                value["lineage_id"],
                "lineage_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            source_event_id=_require_string(
                value["source_event_id"],
                "source_event_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            source_digest=_normalize_digest(None, value["source_digest"], "source_digest"),
            scope=_require_string(
                value["scope"],
                "scope",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            declared_authority=_coerce_enum(
                SourceAuthority, value["declared_authority"], "declared_authority"
            ),
            verified_authority_status=_require_string(
                value["verified_authority_status"],
                "verified_authority_status",
                allow_empty=False,
                max_chars=128,
            ),
            metadata=_coerce_metadata(value.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class ExtractedCandidateRecord:
    """Candidate emitted by a provider extraction step."""

    lineage_id: str
    candidate_id: str
    source_event_id: str
    content_digest: str
    provider_memory_id: str | None = None
    scope: str = "local"
    declared_authority: SourceAuthority = SourceAuthority.UNKNOWN
    verified_authority_status: str = "missing"
    memory_firewall_event_id: str | None = None
    memory_firewall_disposition: RecommendedDisposition | None = None
    memory_firewall_finding_count: int = 0
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("lineage_id", "candidate_id", "source_event_id", "scope"):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        _normalize_digest(None, self.content_digest, "content_digest")
        if self.provider_memory_id is not None:
            _require_string(
                self.provider_memory_id,
                "provider_memory_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        if not isinstance(self.declared_authority, SourceAuthority):
            raise TypeError("declared_authority must be a SourceAuthority")
        _require_string(
            self.verified_authority_status,
            "verified_authority_status",
            allow_empty=False,
            max_chars=128,
        )
        if self.memory_firewall_event_id is not None:
            _require_string(
                self.memory_firewall_event_id,
                "memory_firewall_event_id",
                allow_empty=False,
                max_chars=96,
            )
        if self.memory_firewall_disposition is not None and not isinstance(
            self.memory_firewall_disposition, RecommendedDisposition
        ):
            raise TypeError(
                "memory_firewall_disposition must be a RecommendedDisposition"
            )
        object.__setattr__(
            self,
            "memory_firewall_finding_count",
            _require_non_negative_int(
                self.memory_firewall_finding_count,
                "memory_firewall_finding_count",
            ),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable extracted-candidate record."""

        return {
            "lineage_id": self.lineage_id,
            "candidate_id": self.candidate_id,
            "source_event_id": self.source_event_id,
            "content_digest": self.content_digest,
            "provider_memory_id": self.provider_memory_id,
            "scope": self.scope,
            "declared_authority": self.declared_authority.value,
            "verified_authority_status": self.verified_authority_status,
            "memory_firewall_event_id": self.memory_firewall_event_id,
            "memory_firewall_disposition": (
                None
                if self.memory_firewall_disposition is None
                else self.memory_firewall_disposition.value
            ),
            "memory_firewall_finding_count": self.memory_firewall_finding_count,
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtractedCandidateRecord":
        """Build an extracted-candidate record from a JSON-like mapping."""

        _reject_unknown_fields(value, _CANDIDATE_KEYS, "ExtractedCandidateRecord")
        content = _optional_string(value.get("content"), "content")
        disposition_value = value.get("memory_firewall_disposition")
        return cls(
            lineage_id=_require_string(
                value["lineage_id"],
                "lineage_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            candidate_id=_require_string(
                value["candidate_id"],
                "candidate_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            source_event_id=_require_string(
                value["source_event_id"],
                "source_event_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            content_digest=_normalize_digest(
                content,
                value.get("content_digest"),
                "content_digest",
            ),
            provider_memory_id=_optional_string(
                value.get("provider_memory_id"),
                "provider_memory_id",
            ),
            scope=_require_string(
                value.get("scope", "local"),
                "scope",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            declared_authority=_coerce_enum(
                SourceAuthority,
                value.get("declared_authority", SourceAuthority.UNKNOWN.value),
                "declared_authority",
            ),
            verified_authority_status=_require_string(
                value.get("verified_authority_status", "missing"),
                "verified_authority_status",
                allow_empty=False,
                max_chars=128,
            ),
            memory_firewall_event_id=_optional_string(
                value.get("memory_firewall_event_id"),
                "memory_firewall_event_id",
            ),
            memory_firewall_disposition=(
                None
                if disposition_value is None
                else _coerce_enum(
                    RecommendedDisposition,
                    disposition_value,
                    "memory_firewall_disposition",
                )
            ),
            memory_firewall_finding_count=_require_non_negative_int(
                value.get("memory_firewall_finding_count", 0),
                "memory_firewall_finding_count",
            ),
            metadata=_coerce_metadata(value.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class MemoryFirewallScanRecord:
    lineage_id: str
    memory_firewall_event_id: str
    scan_level: MemoryFirewallScanLevel
    scanned_content_digest: str
    scanned_scope: str
    disposition: RecommendedDisposition
    finding_count: int
    candidate_id: str | None = None
    detector_pack_version: str | None = None
    policy_version: str | None = None
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "lineage_id",
            "memory_firewall_event_id",
            "scanned_scope",
        ):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        if not isinstance(self.scan_level, MemoryFirewallScanLevel):
            raise TypeError("scan_level must be a MemoryFirewallScanLevel")
        _normalize_digest(None, self.scanned_content_digest, "scanned_content_digest")
        if not isinstance(self.disposition, RecommendedDisposition):
            raise TypeError("disposition must be a RecommendedDisposition")
        object.__setattr__(
            self,
            "finding_count",
            _require_non_negative_int(self.finding_count, "finding_count"),
        )
        if (
            self.scan_level == MemoryFirewallScanLevel.CANDIDATE_LEVEL
            and self.candidate_id is None
        ):
            raise ValueError("candidate-level scans require candidate_id")
        for field_name in ("candidate_id", "detector_pack_version", "policy_version"):
            value = getattr(self, field_name)
            if value is not None:
                _require_string(
                    value,
                    field_name,
                    allow_empty=False,
                    max_chars=LINEAGE_MAX_TEXT_CHARS,
                )
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryFirewallScanRecord":
        _reject_unknown_fields(value, _SCAN_KEYS, "MemoryFirewallScanRecord")
        scanned_content = _optional_string(value.get("scanned_content"), "scanned_content")
        return cls(
            lineage_id=_require_string(
                value["lineage_id"],
                "lineage_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            memory_firewall_event_id=_require_string(
                value["memory_firewall_event_id"],
                "memory_firewall_event_id",
                allow_empty=False,
                max_chars=96,
            ),
            candidate_id=_optional_string(value.get("candidate_id"), "candidate_id"),
            scan_level=_coerce_enum(
                MemoryFirewallScanLevel,
                value.get("scan_level", MemoryFirewallScanLevel.CANDIDATE_LEVEL.value),
                "scan_level",
            ),
            scanned_content_digest=_normalize_digest(
                scanned_content,
                value.get("scanned_content_digest"),
                "scanned_content_digest",
            ),
            scanned_scope=_require_string(
                value["scanned_scope"],
                "scanned_scope",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            detector_pack_version=_optional_string(
                value.get("detector_pack_version"),
                "detector_pack_version",
            ),
            policy_version=_optional_string(value.get("policy_version"), "policy_version"),
            disposition=_coerce_enum(
                RecommendedDisposition,
                value["disposition"],
                "disposition",
            ),
            finding_count=_require_non_negative_int(
                value.get("finding_count", 0),
                "finding_count",
            ),
            metadata=_coerce_metadata(value.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class PersistedMemoryRecord:
    """Provider memory record observed after persistence."""

    lineage_id: str
    persisted_record_id: str
    content_digest: str
    provider_memory_id: str | None = None
    scope: str = "local"
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("lineage_id", "persisted_record_id", "scope"):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        _normalize_digest(None, self.content_digest, "content_digest")
        if self.provider_memory_id is not None:
            _require_string(
                self.provider_memory_id,
                "provider_memory_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable persisted-memory record."""

        return {
            "lineage_id": self.lineage_id,
            "persisted_record_id": self.persisted_record_id,
            "provider_memory_id": self.provider_memory_id,
            "content_digest": self.content_digest,
            "scope": self.scope,
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PersistedMemoryRecord":
        """Build a persisted-memory record from a JSON-like mapping."""

        _reject_unknown_fields(value, _PERSISTED_KEYS, "PersistedMemoryRecord")
        content = _optional_string(value.get("content"), "content")
        return cls(
            lineage_id=_require_string(
                value["lineage_id"],
                "lineage_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            persisted_record_id=_require_string(
                value["persisted_record_id"],
                "persisted_record_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            provider_memory_id=_optional_string(
                value.get("provider_memory_id"),
                "provider_memory_id",
            ),
            content_digest=_normalize_digest(
                content,
                value.get("content_digest"),
                "content_digest",
            ),
            scope=_require_string(
                value.get("scope", "local"),
                "scope",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            metadata=_coerce_metadata(value.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class RetrievedMemoryRecord:
    """Provider memory record observed at retrieval time."""

    lineage_id: str
    retrieval_event_id: str
    content_digest: str
    provider_memory_id: str | None = None
    persisted_record_id: str | None = None
    scope: str = "local"
    downstream_used: bool = False
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("lineage_id", "retrieval_event_id", "scope"):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        _normalize_digest(None, self.content_digest, "content_digest")
        for field_name in ("provider_memory_id", "persisted_record_id"):
            value = getattr(self, field_name)
            if value is not None:
                _require_string(
                    value,
                    field_name,
                    allow_empty=False,
                    max_chars=LINEAGE_MAX_TEXT_CHARS,
                )
        object.__setattr__(
            self, "downstream_used", _require_bool(self.downstream_used, "downstream_used")
        )
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable retrieved-memory record."""

        return {
            "lineage_id": self.lineage_id,
            "retrieval_event_id": self.retrieval_event_id,
            "provider_memory_id": self.provider_memory_id,
            "persisted_record_id": self.persisted_record_id,
            "content_digest": self.content_digest,
            "scope": self.scope,
            "downstream_used": self.downstream_used,
            "metadata": _coerce_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RetrievedMemoryRecord":
        """Build a retrieved-memory record from a JSON-like mapping."""

        _reject_unknown_fields(value, _RETRIEVED_KEYS, "RetrievedMemoryRecord")
        content = _optional_string(value.get("content"), "content")
        return cls(
            lineage_id=_require_string(
                value["lineage_id"],
                "lineage_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            retrieval_event_id=_require_string(
                value["retrieval_event_id"],
                "retrieval_event_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            provider_memory_id=_optional_string(
                value.get("provider_memory_id"),
                "provider_memory_id",
            ),
            persisted_record_id=_optional_string(
                value.get("persisted_record_id"),
                "persisted_record_id",
            ),
            content_digest=_normalize_digest(
                content,
                value.get("content_digest"),
                "content_digest",
            ),
            scope=_require_string(
                value.get("scope", "local"),
                "scope",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            ),
            downstream_used=_require_bool(value.get("downstream_used", False), "downstream_used"),
            metadata=_coerce_metadata(value.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class CandidateLineageVerdict:
    """Candidate-level answer to what happened across provider stages."""

    lineage_id: str
    candidate_id: str
    source_event_id: str
    source_digest: str | None
    content_digest: str
    provider_memory_id: str | None
    persisted_record_id: str | None
    retrieval_event_id: str | None
    scope: str
    declared_authority: SourceAuthority
    verified_authority_status: str
    persisted_link_status: LineageLinkStatus
    retrieval_link_status: LineageLinkStatus
    persisted: bool
    retrieved: bool
    downstream_used: bool
    scan_status: CandidateScanStatus
    memory_firewall_event_id: str | None
    memory_firewall_disposition: RecommendedDisposition | None
    memory_firewall_finding_count: int
    case_level_memory_firewall_event_id: str | None = None
    case_level_memory_firewall_disposition: RecommendedDisposition | None = None
    case_level_memory_firewall_finding_count: int = 0
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("lineage_id", "candidate_id", "source_event_id", "scope"):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        if self.source_digest is not None:
            _normalize_digest(None, self.source_digest, "source_digest")
        _normalize_digest(None, self.content_digest, "content_digest")
        for field_name in (
            "provider_memory_id",
            "persisted_record_id",
            "retrieval_event_id",
            "memory_firewall_event_id",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _require_string(
                    value,
                    field_name,
                    allow_empty=False,
                    max_chars=LINEAGE_MAX_TEXT_CHARS,
                )
        if not isinstance(self.declared_authority, SourceAuthority):
            raise TypeError("declared_authority must be a SourceAuthority")
        _require_string(
            self.verified_authority_status,
            "verified_authority_status",
            allow_empty=False,
            max_chars=128,
        )
        for field_name in ("persisted_link_status", "retrieval_link_status"):
            if not isinstance(getattr(self, field_name), LineageLinkStatus):
                raise TypeError(f"{field_name} must be a LineageLinkStatus")
        for field_name in ("persisted", "retrieved", "downstream_used"):
            _require_bool(getattr(self, field_name), field_name)
        if not isinstance(self.scan_status, CandidateScanStatus):
            raise TypeError("scan_status must be a CandidateScanStatus")
        for field_name in (
            "memory_firewall_disposition",
            "case_level_memory_firewall_disposition",
        ):
            disposition = getattr(self, field_name)
            if disposition is not None and not isinstance(
                disposition, RecommendedDisposition
            ):
                raise TypeError(f"{field_name} must be a RecommendedDisposition")
        if self.case_level_memory_firewall_event_id is not None:
            _require_string(
                self.case_level_memory_firewall_event_id,
                "case_level_memory_firewall_event_id",
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        object.__setattr__(
            self,
            "memory_firewall_finding_count",
            _require_non_negative_int(
                self.memory_firewall_finding_count,
                "memory_firewall_finding_count",
            ),
        )
        object.__setattr__(
            self,
            "case_level_memory_firewall_finding_count",
            _require_non_negative_int(
                self.case_level_memory_firewall_finding_count,
                "case_level_memory_firewall_finding_count",
            ),
        )
        object.__setattr__(self, "limitations", _require_tuple(self.limitations, "limitations"))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable candidate verdict."""

        return {
            "lineage_id": self.lineage_id,
            "candidate_id": self.candidate_id,
            "source_event_id": self.source_event_id,
            "source_digest": self.source_digest,
            "content_digest": self.content_digest,
            "provider_memory_id": self.provider_memory_id,
            "persisted_record_id": self.persisted_record_id,
            "retrieval_event_id": self.retrieval_event_id,
            "scope": self.scope,
            "declared_authority": self.declared_authority.value,
            "verified_authority_status": self.verified_authority_status,
            "persisted_link_status": self.persisted_link_status.value,
            "retrieval_link_status": self.retrieval_link_status.value,
            "persisted": self.persisted,
            "retrieved": self.retrieved,
            "downstream_used": self.downstream_used,
            "scan_status": self.scan_status.value,
            "memory_firewall_event_id": self.memory_firewall_event_id,
            "memory_firewall_disposition": (
                None
                if self.memory_firewall_disposition is None
                else self.memory_firewall_disposition.value
            ),
            "memory_firewall_finding_count": self.memory_firewall_finding_count,
            "case_level_memory_firewall_event_id": (
                self.case_level_memory_firewall_event_id
            ),
            "case_level_memory_firewall_disposition": (
                None
                if self.case_level_memory_firewall_disposition is None
                else self.case_level_memory_firewall_disposition.value
            ),
            "case_level_memory_firewall_finding_count": (
                self.case_level_memory_firewall_finding_count
            ),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class LineageIssue:
    """Non-fatal issue found while linking provider-stage evidence."""

    code: str
    message: str
    candidate_id: str | None = None
    provider_memory_id: str | None = None
    persisted_record_id: str | None = None
    retrieval_event_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("code", "message"):
            _require_string(
                getattr(self, field_name),
                field_name,
                allow_empty=False,
                max_chars=LINEAGE_MAX_TEXT_CHARS,
            )
        for field_name in (
            "candidate_id",
            "provider_memory_id",
            "persisted_record_id",
            "retrieval_event_id",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _require_string(
                    value,
                    field_name,
                    allow_empty=False,
                    max_chars=LINEAGE_MAX_TEXT_CHARS,
                )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable issue."""

        return {
            "code": self.code,
            "message": self.message,
            "candidate_id": self.candidate_id,
            "provider_memory_id": self.provider_memory_id,
            "persisted_record_id": self.persisted_record_id,
            "retrieval_event_id": self.retrieval_event_id,
        }


@dataclass(frozen=True, slots=True)
class LineageSummary:
    """Aggregate counts for a stage-aware lineage report."""

    source_events: int
    candidates: int
    persisted_candidates: int
    retrieved_candidates: int
    downstream_used_candidates: int
    candidate_level_verdicts: int
    case_level_only_candidates: int
    unscanned_candidates: int
    unmatched_persisted_records: int
    unmatched_retrievals: int
    scope_mismatches: int
    highest_any_candidate_disposition: RecommendedDisposition
    highest_downstream_used_candidate_disposition: RecommendedDisposition
    downstream_used_candidates_escalated: int
    downstream_used_candidates_unscanned: int

    def __post_init__(self) -> None:
        for field_name in (
            "source_events",
            "candidates",
            "persisted_candidates",
            "retrieved_candidates",
            "downstream_used_candidates",
            "candidate_level_verdicts",
            "case_level_only_candidates",
            "unscanned_candidates",
            "unmatched_persisted_records",
            "unmatched_retrievals",
            "scope_mismatches",
            "downstream_used_candidates_escalated",
            "downstream_used_candidates_unscanned",
        ):
            object.__setattr__(
                self,
                field_name,
                _require_non_negative_int(getattr(self, field_name), field_name),
            )
        for field_name in (
            "highest_any_candidate_disposition",
            "highest_downstream_used_candidate_disposition",
        ):
            if not isinstance(getattr(self, field_name), RecommendedDisposition):
                raise TypeError(f"{field_name} must be a RecommendedDisposition")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary."""

        return {
            "source_events": self.source_events,
            "candidates": self.candidates,
            "persisted_candidates": self.persisted_candidates,
            "retrieved_candidates": self.retrieved_candidates,
            "downstream_used_candidates": self.downstream_used_candidates,
            "candidate_level_verdicts": self.candidate_level_verdicts,
            "case_level_only_candidates": self.case_level_only_candidates,
            "unscanned_candidates": self.unscanned_candidates,
            "unmatched_persisted_records": self.unmatched_persisted_records,
            "unmatched_retrievals": self.unmatched_retrievals,
            "scope_mismatches": self.scope_mismatches,
            "highest_any_candidate_disposition": (
                self.highest_any_candidate_disposition.value
            ),
            "highest_downstream_used_candidate_disposition": (
                self.highest_downstream_used_candidate_disposition.value
            ),
            "downstream_used_candidates_escalated": (
                self.downstream_used_candidates_escalated
            ),
            "downstream_used_candidates_unscanned": (
                self.downstream_used_candidates_unscanned
            ),
        }


@dataclass(frozen=True, slots=True)
class LineageReport:
    """Candidate-level lineage report over one evidence packet."""

    lineage_version: str
    provider: str
    provider_version: str
    summary: LineageSummary
    candidate_verdicts: tuple[CandidateLineageVerdict, ...]
    issues: tuple[LineageIssue, ...]
    non_goals: tuple[str, ...]
    metadata: Mapping[str, JSONScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.lineage_version != LINEAGE_VERSION:
            raise ValueError(f"lineage_version must be {LINEAGE_VERSION}")
        _require_string(self.provider, "provider", allow_empty=False, max_chars=256)
        _require_string(
            self.provider_version,
            "provider_version",
            allow_empty=False,
            max_chars=256,
        )
        if not isinstance(self.summary, LineageSummary):
            raise TypeError("summary must be a LineageSummary")
        if any(not isinstance(item, CandidateLineageVerdict) for item in self.candidate_verdicts):
            raise TypeError("candidate_verdicts must contain CandidateLineageVerdict")
        if any(not isinstance(item, LineageIssue) for item in self.issues):
            raise TypeError("issues must contain LineageIssue")
        object.__setattr__(self, "non_goals", _require_tuple(self.non_goals, "non_goals"))
        object.__setattr__(self, "metadata", MappingProxyType(_coerce_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable lineage report."""

        return {
            "lineage_version": self.lineage_version,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "summary": self.summary.to_dict(),
            "candidate_verdicts": [item.to_dict() for item in self.candidate_verdicts],
            "issues": [item.to_dict() for item in self.issues],
            "non_goals": list(self.non_goals),
            "metadata": _coerce_metadata(self.metadata),
        }


def _records_from_payload(
    payload: Mapping[str, Any],
) -> tuple[
    tuple[ObservedSourceRecord, ...],
    tuple[ExtractedCandidateRecord, ...],
    tuple[MemoryFirewallScanRecord, ...],
    tuple[PersistedMemoryRecord, ...],
    tuple[RetrievedMemoryRecord, ...],
]:
    return (
        tuple(ObservedSourceRecord.from_dict(item) for item in payload["source_events"]),
        tuple(
            ExtractedCandidateRecord.from_dict(item)
            for item in payload["extracted_candidates"]
        ),
        tuple(
            MemoryFirewallScanRecord.from_dict(item)
            for item in payload.get("memory_firewall_scans", [])
        ),
        tuple(
            PersistedMemoryRecord.from_dict(item)
            for item in payload["persisted_memories"]
        ),
        tuple(
            RetrievedMemoryRecord.from_dict(item)
            for item in payload["retrieved_memories"]
        ),
    )


@dataclass(frozen=True, slots=True)
class _PersistedStageMatch:
    record: PersistedMemoryRecord | None
    status: LineageLinkStatus
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RetrievedStageMatch:
    record: RetrievedMemoryRecord | None
    status: LineageLinkStatus
    limitations: tuple[str, ...]


def _record_key(record: PersistedMemoryRecord | RetrievedMemoryRecord) -> tuple[str, str] | None:
    if record.provider_memory_id is None:
        return None
    return (record.lineage_id, record.provider_memory_id)


def _source_key(record: ObservedSourceRecord) -> tuple[str, str]:
    return (record.lineage_id, record.source_event_id)


def _candidate_key(record: ExtractedCandidateRecord) -> tuple[str, str]:
    return (record.lineage_id, record.candidate_id)


def _scan_key(record: MemoryFirewallScanRecord) -> tuple[str, str | None]:
    return (record.lineage_id, record.candidate_id)


def _persisted_record_key(record: PersistedMemoryRecord) -> tuple[str, str]:
    return (record.lineage_id, record.persisted_record_id)


def _retrieval_record_key(record: RetrievedMemoryRecord) -> tuple[str, str]:
    return (record.lineage_id, record.retrieval_event_id)


def _retrieved_persisted_key(record: RetrievedMemoryRecord) -> tuple[str, str] | None:
    if record.persisted_record_id is None:
        return None
    return (record.lineage_id, record.persisted_record_id)


def _digest_key(record: PersistedMemoryRecord | RetrievedMemoryRecord) -> tuple[str, str]:
    return (record.lineage_id, record.content_digest)


def _index_many_persisted(
    records: tuple[PersistedMemoryRecord, ...],
    keys: tuple[tuple[str, str] | None, ...],
) -> dict[tuple[str, str], tuple[PersistedMemoryRecord, ...]]:
    index: dict[tuple[str, str], list[PersistedMemoryRecord]] = {}
    for record, key in zip(records, keys, strict=True):
        if key is not None:
            index.setdefault(key, []).append(record)
    return {key: tuple(items) for key, items in index.items()}


def _index_many_retrieved(
    records: tuple[RetrievedMemoryRecord, ...],
    keys: tuple[tuple[str, str] | None, ...],
) -> dict[tuple[str, str], tuple[RetrievedMemoryRecord, ...]]:
    index: dict[tuple[str, str], list[RetrievedMemoryRecord]] = {}
    for record, key in zip(records, keys, strict=True):
        if key is not None:
            index.setdefault(key, []).append(record)
    return {key: tuple(items) for key, items in index.items()}


def _source_index(
    records: tuple[ObservedSourceRecord, ...],
) -> dict[tuple[str, str], tuple[ObservedSourceRecord, ...]]:
    index: dict[tuple[str, str], list[ObservedSourceRecord]] = {}
    for record in records:
        index.setdefault(_source_key(record), []).append(record)
    return {key: tuple(items) for key, items in index.items()}


def _candidate_index(
    records: tuple[ExtractedCandidateRecord, ...],
) -> dict[tuple[str, str], tuple[ExtractedCandidateRecord, ...]]:
    index: dict[tuple[str, str], list[ExtractedCandidateRecord]] = {}
    for record in records:
        index.setdefault(_candidate_key(record), []).append(record)
    return {key: tuple(items) for key, items in index.items()}


def _scan_index(
    records: tuple[MemoryFirewallScanRecord, ...],
) -> dict[tuple[str, str | None], tuple[MemoryFirewallScanRecord, ...]]:
    index: dict[tuple[str, str | None], list[MemoryFirewallScanRecord]] = {}
    for record in records:
        index.setdefault(_scan_key(record), []).append(record)
    return {key: tuple(items) for key, items in index.items()}


def _scan_event_index(
    records: tuple[MemoryFirewallScanRecord, ...],
) -> dict[tuple[str, str], tuple[MemoryFirewallScanRecord, ...]]:
    index: dict[tuple[str, str], list[MemoryFirewallScanRecord]] = {}
    for record in records:
        index.setdefault((record.lineage_id, record.memory_firewall_event_id), []).append(
            record
        )
    return {key: tuple(items) for key, items in index.items()}


def _match_persisted(
    candidate: ExtractedCandidateRecord,
    persisted_by_provider: Mapping[tuple[str, str], tuple[PersistedMemoryRecord, ...]],
    persisted_by_digest: Mapping[tuple[str, str], tuple[PersistedMemoryRecord, ...]],
) -> _PersistedStageMatch:
    limitations: list[str] = []
    if candidate.provider_memory_id is not None:
        provider_matches = persisted_by_provider.get(
            (candidate.lineage_id, candidate.provider_memory_id),
            (),
        )
        if len(provider_matches) > 1:
            limitations.append("multiple persisted records share provider memory id")
            return _PersistedStageMatch(
                None,
                LineageLinkStatus.AMBIGUOUS_MATCH,
                tuple(limitations),
            )
        if len(provider_matches) == 1:
            provider_match = provider_matches[0]
            if provider_match.scope != candidate.scope:
                limitations.append("provider id matched but persisted scope differs")
                return _PersistedStageMatch(
                    provider_match,
                    LineageLinkStatus.SCOPE_MISMATCH,
                    tuple(limitations),
                )
            if provider_match.content_digest != candidate.content_digest:
                limitations.append("provider id matched but persisted content digest differs")
                return _PersistedStageMatch(
                    provider_match,
                    LineageLinkStatus.CONTENT_MISMATCH,
                    tuple(limitations),
                )
            return _PersistedStageMatch(
                provider_match,
                LineageLinkStatus.EXACT_PROVIDER_ID_AND_DIGEST,
                (),
            )
        limitations.append("provider_id_unmatched")
    else:
        limitations.append("provider_id_absent")
    digest_matches = persisted_by_digest.get((candidate.lineage_id, candidate.content_digest), ())
    if len(digest_matches) > 1:
        limitations.append("multiple persisted records share content digest")
        return _PersistedStageMatch(
            None,
            LineageLinkStatus.AMBIGUOUS_MATCH,
            tuple(limitations),
        )
    if len(digest_matches) == 1:
        digest_match = digest_matches[0]
        if digest_match.scope != candidate.scope:
            limitations.append("content digest matched but persisted scope differs")
            return _PersistedStageMatch(
                digest_match,
                LineageLinkStatus.SCOPE_MISMATCH,
                tuple(limitations),
            )
        limitations.append(
            "Provider-ID linkage was unavailable; matched by unique exact content digest"
        )
        return _PersistedStageMatch(
            digest_match,
            LineageLinkStatus.UNIQUE_CONTENT_DIGEST,
            tuple(limitations),
        )
    limitations.append("candidate was not linked to persisted memory")
    return _PersistedStageMatch(None, LineageLinkStatus.NOT_LINKED, tuple(limitations))


def _match_retrieved(
    candidate: ExtractedCandidateRecord,
    persisted: PersistedMemoryRecord | None,
    retrieved_by_provider: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
    retrieved_by_persisted_id: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
    retrieved_by_digest: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
) -> _RetrievedStageMatch:
    limitations: list[str] = []
    if candidate.provider_memory_id is not None:
        provider_matches = retrieved_by_provider.get(
            (candidate.lineage_id, candidate.provider_memory_id),
            (),
        )
        if len(provider_matches) > 1:
            limitations.append("multiple retrieved records share provider memory id")
            return _RetrievedStageMatch(
                None,
                LineageLinkStatus.AMBIGUOUS_MATCH,
                tuple(limitations),
            )
        if len(provider_matches) == 1:
            provider_match = provider_matches[0]
            if provider_match.scope != candidate.scope:
                limitations.append("provider id matched but retrieval scope differs")
                return _RetrievedStageMatch(
                    provider_match,
                    LineageLinkStatus.SCOPE_MISMATCH,
                    tuple(limitations),
                )
            if provider_match.content_digest != candidate.content_digest:
                limitations.append("provider id matched but retrieval content digest differs")
                return _RetrievedStageMatch(
                    provider_match,
                    LineageLinkStatus.CONTENT_MISMATCH,
                    tuple(limitations),
                )
            if (
                persisted is not None
                and provider_match.persisted_record_id is not None
                and provider_match.persisted_record_id != persisted.persisted_record_id
            ):
                limitations.append("retrieval persisted id disagrees with persisted record")
                return _RetrievedStageMatch(
                    provider_match,
                    LineageLinkStatus.CHAIN_INCONSISTENT,
                    tuple(limitations),
                )
            return _RetrievedStageMatch(
                provider_match,
                LineageLinkStatus.EXACT_PROVIDER_ID_AND_DIGEST,
                tuple(limitations),
            )
    if persisted is not None:
        persisted_matches = retrieved_by_persisted_id.get(
            (persisted.lineage_id, persisted.persisted_record_id),
            (),
        )
        if len(persisted_matches) > 1:
            limitations.append("multiple retrieved records share persisted record id")
            return _RetrievedStageMatch(
                None,
                LineageLinkStatus.AMBIGUOUS_MATCH,
                tuple(limitations),
            )
        if len(persisted_matches) == 1:
            persisted_match = persisted_matches[0]
            if persisted_match.scope != candidate.scope:
                limitations.append("persisted id matched but retrieval scope differs")
                return _RetrievedStageMatch(
                    persisted_match,
                    LineageLinkStatus.SCOPE_MISMATCH,
                    tuple(limitations),
                )
            if persisted_match.content_digest != candidate.content_digest:
                limitations.append("persisted id matched but retrieval content digest differs")
                return _RetrievedStageMatch(
                    persisted_match,
                    LineageLinkStatus.CONTENT_MISMATCH,
                    tuple(limitations),
                )
            if (
                persisted.provider_memory_id is not None
                and persisted_match.provider_memory_id is not None
                and persisted.provider_memory_id != persisted_match.provider_memory_id
            ):
                limitations.append("retrieval provider id disagrees with persisted record")
                return _RetrievedStageMatch(
                    persisted_match,
                    LineageLinkStatus.CHAIN_INCONSISTENT,
                    tuple(limitations),
                )
            return _RetrievedStageMatch(
                persisted_match,
                LineageLinkStatus.EXACT_PERSISTED_ID_AND_DIGEST,
                tuple(limitations),
            )
    digest_matches = retrieved_by_digest.get((candidate.lineage_id, candidate.content_digest), ())
    if len(digest_matches) > 1:
        limitations.append("multiple retrieved records share content digest")
        return _RetrievedStageMatch(
            None,
            LineageLinkStatus.AMBIGUOUS_MATCH,
            tuple(limitations),
        )
    if len(digest_matches) == 1:
        digest_match = digest_matches[0]
        if digest_match.scope != candidate.scope:
            limitations.append("content digest matched but retrieval scope differs")
            return _RetrievedStageMatch(
                digest_match,
                LineageLinkStatus.SCOPE_MISMATCH,
                tuple(limitations),
            )
        limitations.append("retrieval matched by content digest")
        return _RetrievedStageMatch(
            digest_match,
            LineageLinkStatus.UNIQUE_CONTENT_DIGEST,
            tuple(limitations),
        )
    return _RetrievedStageMatch(
        None,
        LineageLinkStatus.NOT_LINKED,
        ("candidate was not linked to retrieved memory",),
    )


def _link_succeeded(status: LineageLinkStatus) -> bool:
    return status in (
        LineageLinkStatus.EXACT_PROVIDER_ID_AND_DIGEST,
        LineageLinkStatus.EXACT_PERSISTED_ID_AND_DIGEST,
        LineageLinkStatus.UNIQUE_CONTENT_DIGEST,
    )


def _scan_matches_candidate(
    candidate: ExtractedCandidateRecord,
    scan: MemoryFirewallScanRecord,
) -> bool:
    return (
        scan.scan_level == MemoryFirewallScanLevel.CANDIDATE_LEVEL
        and scan.candidate_id == candidate.candidate_id
        and scan.scanned_content_digest == candidate.content_digest
        and scan.scanned_scope == candidate.scope
    )


def _case_level_scan_for_candidate(
    candidate: ExtractedCandidateRecord,
    scans: tuple[MemoryFirewallScanRecord, ...],
) -> tuple[MemoryFirewallScanRecord | None, tuple[LineageIssue, ...]]:
    case_scans = [
        scan
        for scan in scans
        if scan.scan_level == MemoryFirewallScanLevel.CASE_LEVEL_ONLY
        and scan.lineage_id == candidate.lineage_id
        and (scan.candidate_id is None or scan.candidate_id == candidate.candidate_id)
    ]
    if not case_scans:
        return None, ()
    if len(case_scans) > 1:
        return None, (
            LineageIssue(
                code="ambiguous_case_level_scan",
                message="multiple case-level scan records apply to candidate",
                candidate_id=candidate.candidate_id,
                provider_memory_id=candidate.provider_memory_id,
            ),
        )
    return case_scans[0], ()


def _candidate_scan_evidence(
    candidate: ExtractedCandidateRecord,
    scans: tuple[MemoryFirewallScanRecord, ...],
) -> tuple[
    CandidateScanStatus,
    MemoryFirewallScanRecord | None,
    MemoryFirewallScanRecord | None,
    tuple[str, ...],
    tuple[LineageIssue, ...],
]:
    issues: list[LineageIssue] = []
    limitations: list[str] = []
    candidate_scans = [
        scan
        for scan in scans
        if scan.lineage_id == candidate.lineage_id
        and scan.candidate_id == candidate.candidate_id
        and scan.scan_level == MemoryFirewallScanLevel.CANDIDATE_LEVEL
    ]
    matching_scans = [
        scan for scan in candidate_scans if _scan_matches_candidate(candidate, scan)
    ]
    case_scan, case_scan_issues = _case_level_scan_for_candidate(candidate, scans)
    issues.extend(case_scan_issues)
    if len(candidate_scans) > 1:
        issues.append(
            LineageIssue(
                code="duplicate_candidate_scan",
                message="multiple candidate-level scan records target this candidate",
                candidate_id=candidate.candidate_id,
                provider_memory_id=candidate.provider_memory_id,
            )
        )
    if candidate_scans and not matching_scans:
        issues.append(
            LineageIssue(
                code="candidate_scan_mismatch",
                message="candidate-level scan record does not match candidate digest and scope",
                candidate_id=candidate.candidate_id,
                provider_memory_id=candidate.provider_memory_id,
            )
        )
    if matching_scans:
        scan = matching_scans[0]
        if candidate.memory_firewall_event_id is not None and (
            candidate.memory_firewall_event_id != scan.memory_firewall_event_id
        ):
            issues.append(
                LineageIssue(
                    code="candidate_scan_claim_mismatch",
                    message="candidate-supplied scan event id disagrees with scan evidence",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                )
            )
        if candidate.memory_firewall_disposition is not None and (
            candidate.memory_firewall_disposition != scan.disposition
        ):
            issues.append(
                LineageIssue(
                    code="candidate_scan_claim_mismatch",
                    message="candidate-supplied disposition disagrees with scan evidence",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                )
            )
        if (
            (
                candidate.memory_firewall_event_id is not None
                or candidate.memory_firewall_disposition is not None
                or candidate.memory_firewall_finding_count > 0
            )
            and candidate.memory_firewall_finding_count != scan.finding_count
        ):
            issues.append(
                LineageIssue(
                    code="candidate_scan_claim_mismatch",
                    message="candidate-supplied finding count disagrees with scan evidence",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                )
            )
        return (
            CandidateScanStatus.CANDIDATE_LEVEL,
            scan,
            case_scan,
            tuple(limitations),
            tuple(issues),
        )
    if (
        candidate.memory_firewall_event_id is not None
        or candidate.memory_firewall_disposition is not None
        or candidate.memory_firewall_finding_count > 0
    ):
        issues.append(
            LineageIssue(
                code="candidate_scan_claim_without_scan_record",
                message="candidate carries scan claims but no matching scan evidence record",
                candidate_id=candidate.candidate_id,
                provider_memory_id=candidate.provider_memory_id,
            )
        )
    if case_scan is not None:
        limitations.append("Memory Firewall verdict is case-level, not candidate-level")
        return (
            CandidateScanStatus.CASE_LEVEL_ONLY,
            None,
            case_scan,
            tuple(limitations),
            tuple(issues),
        )
    return (
        CandidateScanStatus.NOT_SCANNED,
        None,
        None,
        tuple(limitations),
        tuple(issues),
    )


def _unmatched_persisted_count(
    persisted: tuple[PersistedMemoryRecord, ...],
    matched_ids: set[tuple[str, str]],
) -> int:
    return sum(1 for item in persisted if _persisted_record_key(item) not in matched_ids)


def _unmatched_retrieval_count(
    retrieved: tuple[RetrievedMemoryRecord, ...],
    matched_ids: set[tuple[str, str]],
) -> int:
    return sum(1 for item in retrieved if _retrieval_record_key(item) not in matched_ids)


def _build_issues(
    verdicts: tuple[CandidateLineageVerdict, ...],
    persisted: tuple[PersistedMemoryRecord, ...],
    retrieved: tuple[RetrievedMemoryRecord, ...],
    matched_persisted: set[tuple[str, str]],
    matched_retrieved: set[tuple[str, str]],
    extra_issues: tuple[LineageIssue, ...],
) -> tuple[LineageIssue, ...]:
    issues: list[LineageIssue] = list(extra_issues)
    persisted_to_candidates: dict[tuple[str, str], list[str]] = {}
    retrieved_to_candidates: dict[tuple[str, str], list[str]] = {}
    for verdict in verdicts:
        if verdict.persisted and verdict.persisted_record_id is not None:
            persisted_to_candidates.setdefault(
                (verdict.lineage_id, verdict.persisted_record_id),
                [],
            ).append(verdict.candidate_id)
        if verdict.retrieved and verdict.retrieval_event_id is not None:
            retrieved_to_candidates.setdefault(
                (verdict.lineage_id, verdict.retrieval_event_id),
                [],
            ).append(verdict.candidate_id)
    for (_lineage_id, persisted_record_id), candidate_ids in persisted_to_candidates.items():
        if len(set(candidate_ids)) > 1:
            issues.append(
                LineageIssue(
                    code="multiple_candidates_same_persisted_record",
                    message="multiple candidates link to the same persisted provider record",
                    candidate_id=",".join(sorted(set(candidate_ids))),
                    persisted_record_id=persisted_record_id,
                )
            )
    for (_lineage_id, retrieval_event_id), candidate_ids in retrieved_to_candidates.items():
        if len(set(candidate_ids)) > 1:
            issues.append(
                LineageIssue(
                    code="multiple_candidates_same_retrieval_record",
                    message="multiple candidates link to the same retrieved provider record",
                    candidate_id=",".join(sorted(set(candidate_ids))),
                    retrieval_event_id=retrieval_event_id,
                )
            )
    for verdict in verdicts:
        if verdict.source_digest is None:
            issues.append(
                LineageIssue(
                    code="missing_source_event",
                    message="candidate has no matching source event in the lineage packet",
                    candidate_id=verdict.candidate_id,
                    provider_memory_id=verdict.provider_memory_id,
                    persisted_record_id=verdict.persisted_record_id,
                    retrieval_event_id=verdict.retrieval_event_id,
                )
            )
        for field_name, link_status in (
            ("persisted", verdict.persisted_link_status),
            ("retrieval", verdict.retrieval_link_status),
        ):
            if link_status in (
                LineageLinkStatus.SCOPE_MISMATCH,
                LineageLinkStatus.CONTENT_MISMATCH,
                LineageLinkStatus.AMBIGUOUS_MATCH,
                LineageLinkStatus.CHAIN_INCONSISTENT,
            ):
                issues.append(
                    LineageIssue(
                        code=f"{field_name}_{link_status.value}",
                        message=f"{field_name} lineage link is {link_status.value}",
                        candidate_id=verdict.candidate_id,
                        provider_memory_id=verdict.provider_memory_id,
                        persisted_record_id=verdict.persisted_record_id,
                        retrieval_event_id=verdict.retrieval_event_id,
                    )
                )
        if (
            verdict.retrieved
            and not verdict.persisted
            and verdict.retrieval_link_status != LineageLinkStatus.NOT_LINKED
        ):
            issues.append(
                LineageIssue(
                    code="retrieval_without_persisted_evidence",
                    message="retrieval linked to candidate without complete persistence evidence",
                    candidate_id=verdict.candidate_id,
                    provider_memory_id=verdict.provider_memory_id,
                    persisted_record_id=verdict.persisted_record_id,
                    retrieval_event_id=verdict.retrieval_event_id,
                )
            )
        if verdict.downstream_used and (
            verdict.persisted_link_status == LineageLinkStatus.UNIQUE_CONTENT_DIGEST
            or verdict.retrieval_link_status == LineageLinkStatus.UNIQUE_CONTENT_DIGEST
        ):
            issues.append(
                LineageIssue(
                    code="downstream_candidate_weak_lineage",
                    message="downstream-used candidate relies on digest-only linkage",
                    candidate_id=verdict.candidate_id,
                    provider_memory_id=verdict.provider_memory_id,
                    persisted_record_id=verdict.persisted_record_id,
                    retrieval_event_id=verdict.retrieval_event_id,
                )
            )
        if verdict.downstream_used and verdict.scan_status != CandidateScanStatus.CANDIDATE_LEVEL:
            issues.append(
                LineageIssue(
                    code="downstream_candidate_without_candidate_level_scan",
                    message="downstream-used candidate lacks a candidate-level Memory Firewall verdict",
                    candidate_id=verdict.candidate_id,
                    provider_memory_id=verdict.provider_memory_id,
                    persisted_record_id=verdict.persisted_record_id,
                    retrieval_event_id=verdict.retrieval_event_id,
                )
            )
        if verdict.downstream_used and verdict.memory_firewall_disposition not in (
            RecommendedDisposition.REVIEW,
            RecommendedDisposition.QUARANTINE,
        ):
            issues.append(
                LineageIssue(
                    code="downstream_candidate_not_escalated",
                    message="downstream-used candidate was not individually escalated to review or quarantine",
                    candidate_id=verdict.candidate_id,
                    provider_memory_id=verdict.provider_memory_id,
                    persisted_record_id=verdict.persisted_record_id,
                    retrieval_event_id=verdict.retrieval_event_id,
                )
            )
    for persisted_record in persisted:
        if _persisted_record_key(persisted_record) not in matched_persisted:
            issues.append(
                LineageIssue(
                    code="unmatched_persisted_record",
                    message="persisted provider record was not linked to an extracted candidate",
                    provider_memory_id=persisted_record.provider_memory_id,
                    persisted_record_id=persisted_record.persisted_record_id,
                )
            )
    for retrieved_record in retrieved:
        if _retrieval_record_key(retrieved_record) not in matched_retrieved:
            issues.append(
                LineageIssue(
                    code="unmatched_retrieval",
                    message="retrieved provider record was not linked to an extracted candidate",
                    provider_memory_id=retrieved_record.provider_memory_id,
                    persisted_record_id=retrieved_record.persisted_record_id,
                    retrieval_event_id=retrieved_record.retrieval_event_id,
                )
            )
    return tuple(issues)


def _duplicate_index_issues(
    sources_by_key: Mapping[tuple[str, str], tuple[ObservedSourceRecord, ...]],
    candidates_by_key: Mapping[tuple[str, str], tuple[ExtractedCandidateRecord, ...]],
    scans_by_event: Mapping[tuple[str, str], tuple[MemoryFirewallScanRecord, ...]],
    persisted_by_provider: Mapping[tuple[str, str], tuple[PersistedMemoryRecord, ...]],
    persisted_by_record_id: Mapping[tuple[str, str], tuple[PersistedMemoryRecord, ...]],
    persisted_by_digest: Mapping[tuple[str, str], tuple[PersistedMemoryRecord, ...]],
    retrieved_by_provider: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
    retrieved_by_event_id: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
    retrieved_by_persisted_id: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
    retrieved_by_digest: Mapping[tuple[str, str], tuple[RetrievedMemoryRecord, ...]],
) -> tuple[LineageIssue, ...]:
    issues: list[LineageIssue] = []
    for (lineage_id, source_event_id), source_records in sources_by_key.items():
        if len(source_records) > 1:
            issues.append(
                LineageIssue(
                    code="ambiguous_source_event",
                    message="multiple source records share lineage and source event id",
                    candidate_id=f"{lineage_id}:{source_event_id}",
                )
            )
    for (_lineage_id, candidate_id), candidate_records in candidates_by_key.items():
        if len(candidate_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_candidate_id",
                    message="multiple candidates share lineage and candidate id",
                    candidate_id=candidate_id,
                )
            )
    for (_lineage_id, event_id), scan_records in scans_by_event.items():
        if len(scan_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_scan_event_id",
                    message="multiple Memory Firewall scan records share event id",
                    candidate_id=event_id,
                )
            )
    for scan_records in scans_by_event.values():
        for scan_record in scan_records:
            if (
                scan_record.scan_level == MemoryFirewallScanLevel.CANDIDATE_LEVEL
                and scan_record.candidate_id is not None
                and (scan_record.lineage_id, scan_record.candidate_id)
                not in candidates_by_key
            ):
                issues.append(
                    LineageIssue(
                        code="orphan_candidate_scan",
                        message="candidate-level scan targets no candidate in this packet",
                        candidate_id=scan_record.candidate_id,
                    )
                )
    for (_lineage_id, provider_memory_id), persisted_provider_records in (
        persisted_by_provider.items()
    ):
        if len(persisted_provider_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_provider_id",
                    message="multiple persisted records share provider memory id",
                    provider_memory_id=provider_memory_id,
                )
            )
    for (_lineage_id, persisted_record_id), persisted_id_records in (
        persisted_by_record_id.items()
    ):
        if len(persisted_id_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_persisted_record_id",
                    message="multiple persisted records share persisted record id",
                    persisted_record_id=persisted_record_id,
                )
            )
    for (_lineage_id, _digest), persisted_digest_records in persisted_by_digest.items():
        if len(persisted_digest_records) > 1:
            issues.append(
                LineageIssue(
                    code="ambiguous_persisted_content_digest",
                    message="multiple persisted records share content digest",
                )
            )
    for (_lineage_id, provider_memory_id), retrieved_provider_records in (
        retrieved_by_provider.items()
    ):
        if len(retrieved_provider_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_retrieval_provider_id",
                    message="multiple retrieved records share provider memory id",
                    provider_memory_id=provider_memory_id,
                )
            )
    for (_lineage_id, retrieval_event_id), retrieved_event_records in (
        retrieved_by_event_id.items()
    ):
        if len(retrieved_event_records) > 1:
            issues.append(
                LineageIssue(
                    code="duplicate_retrieval_event_id",
                    message="multiple retrieved records share retrieval event id",
                    retrieval_event_id=retrieval_event_id,
                )
            )
    for (_lineage_id, persisted_record_id), retrieved_persisted_records in (
        retrieved_by_persisted_id.items()
    ):
        if len(retrieved_persisted_records) > 1:
            issues.append(
                LineageIssue(
                    code="ambiguous_retrieved_persisted_record_id",
                    message="multiple retrieved records share persisted record id",
                    persisted_record_id=persisted_record_id,
                )
            )
    for (_lineage_id, _digest), retrieved_digest_records in retrieved_by_digest.items():
        if len(retrieved_digest_records) > 1:
            issues.append(
                LineageIssue(
                    code="ambiguous_retrieved_content_digest",
                    message="multiple retrieved records share content digest",
                )
            )
    return tuple(issues)


def generate_lineage_report(value: Mapping[str, Any]) -> LineageReport:
    """Generate a candidate-level lineage report from a JSON-like packet."""

    _reject_unknown_fields(value, _REPORT_KEYS, "LineageReportInput")
    if value.get("lineage_version", LINEAGE_VERSION) != LINEAGE_VERSION:
        raise ValueError(f"lineage_version must be {LINEAGE_VERSION}")
    provider = _require_string(
        value["provider"], "provider", allow_empty=False, max_chars=256
    )
    provider_version = _require_string(
        value["provider_version"],
        "provider_version",
        allow_empty=False,
        max_chars=256,
    )
    sources, candidates, scans, persisted, retrieved = _records_from_payload(value)
    sources_by_key = _source_index(sources)
    candidates_by_key = _candidate_index(candidates)
    scans_by_candidate = _scan_index(scans)
    scans_by_event = _scan_event_index(scans)
    persisted_by_provider = _index_many_persisted(
        persisted,
        tuple(_record_key(item) for item in persisted),
    )
    persisted_by_record_id = _index_many_persisted(
        persisted,
        tuple(_persisted_record_key(item) for item in persisted),
    )
    persisted_by_digest = _index_many_persisted(
        persisted,
        tuple(_digest_key(item) for item in persisted),
    )
    retrieved_by_provider = _index_many_retrieved(
        retrieved,
        tuple(_record_key(item) for item in retrieved),
    )
    retrieved_by_event_id = _index_many_retrieved(
        retrieved,
        tuple(_retrieval_record_key(item) for item in retrieved),
    )
    retrieved_by_persisted_id = _index_many_retrieved(
        retrieved,
        tuple(_retrieved_persisted_key(item) for item in retrieved),
    )
    retrieved_by_digest = _index_many_retrieved(
        retrieved,
        tuple(_digest_key(item) for item in retrieved),
    )
    extra_issues = list(
        _duplicate_index_issues(
            sources_by_key,
            candidates_by_key,
            scans_by_event,
            persisted_by_provider,
            persisted_by_record_id,
            persisted_by_digest,
            retrieved_by_provider,
            retrieved_by_event_id,
            retrieved_by_persisted_id,
            retrieved_by_digest,
        )
    )
    verdicts: list[CandidateLineageVerdict] = []
    matched_persisted: set[tuple[str, str]] = set()
    matched_retrieved: set[tuple[str, str]] = set()
    for candidate in candidates:
        source_matches = sources_by_key.get(
            (candidate.lineage_id, candidate.source_event_id),
            (),
        )
        source = source_matches[0] if len(source_matches) == 1 else None
        if source is not None and source.scope != candidate.scope:
            extra_issues.append(
                LineageIssue(
                    code="source_scope_mismatch",
                    message="candidate source scope differs from candidate scope",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                )
            )
        if source is not None and (
            source.declared_authority != candidate.declared_authority
            or source.verified_authority_status != candidate.verified_authority_status
        ):
            extra_issues.append(
                LineageIssue(
                    code="candidate_authority_differs_from_source",
                    message="candidate authority differs from source authority without promotion evidence",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                )
            )
        persisted_stage = _match_persisted(
            candidate,
            persisted_by_provider,
            persisted_by_digest,
        )
        persisted_match = persisted_stage.record
        retrieved_stage = _match_retrieved(
            candidate,
            persisted_match,
            retrieved_by_provider,
            retrieved_by_persisted_id,
            retrieved_by_digest,
        )
        retrieved_match = retrieved_stage.record
        if persisted_match is not None and _link_succeeded(persisted_stage.status):
            matched_persisted.add(_persisted_record_key(persisted_match))
        if retrieved_match is not None and _link_succeeded(retrieved_stage.status):
            matched_retrieved.add(_retrieval_record_key(retrieved_match))
        raw_downstream_used = (
            False if retrieved_match is None else retrieved_match.downstream_used
        )
        downstream_used = _link_succeeded(retrieved_stage.status) and raw_downstream_used
        if raw_downstream_used and not _link_succeeded(retrieved_stage.status):
            extra_issues.append(
                LineageIssue(
                    code="unlinked_retrieval_marked_downstream_used",
                    message="retrieval record claimed downstream use but was not cleanly linked",
                    candidate_id=candidate.candidate_id,
                    provider_memory_id=candidate.provider_memory_id,
                    persisted_record_id=(
                        None
                        if persisted_match is None
                        else persisted_match.persisted_record_id
                    ),
                    retrieval_event_id=(
                        None
                        if retrieved_match is None
                        else retrieved_match.retrieval_event_id
                    ),
                )
            )
        scan_status, candidate_scan, case_scan, scan_limitations, scan_issues = (
            _candidate_scan_evidence(
                candidate,
                scans_by_candidate.get((candidate.lineage_id, candidate.candidate_id), ())
                + scans_by_candidate.get((candidate.lineage_id, None), ()),
            )
        )
        extra_issues.extend(scan_issues)
        limitations = list(persisted_stage.limitations)
        limitations.extend(retrieved_stage.limitations)
        limitations.extend(scan_limitations)
        if source is None:
            limitations.append("source event was not present in lineage packet")
        verdicts.append(
            CandidateLineageVerdict(
                lineage_id=candidate.lineage_id,
                candidate_id=candidate.candidate_id,
                source_event_id=candidate.source_event_id,
                source_digest=None if source is None else source.source_digest,
                content_digest=candidate.content_digest,
                provider_memory_id=candidate.provider_memory_id,
                persisted_record_id=(
                    None if persisted_match is None else persisted_match.persisted_record_id
                ),
                retrieval_event_id=(
                    None if retrieved_match is None else retrieved_match.retrieval_event_id
                ),
                scope=candidate.scope,
                declared_authority=candidate.declared_authority,
                verified_authority_status=candidate.verified_authority_status,
                persisted_link_status=persisted_stage.status,
                retrieval_link_status=retrieved_stage.status,
                persisted=_link_succeeded(persisted_stage.status),
                retrieved=_link_succeeded(retrieved_stage.status),
                downstream_used=downstream_used,
                scan_status=scan_status,
                memory_firewall_event_id=(
                    None if candidate_scan is None else candidate_scan.memory_firewall_event_id
                ),
                memory_firewall_disposition=(
                    None if candidate_scan is None else candidate_scan.disposition
                ),
                memory_firewall_finding_count=(
                    0 if candidate_scan is None else candidate_scan.finding_count
                ),
                case_level_memory_firewall_event_id=(
                    None if case_scan is None else case_scan.memory_firewall_event_id
                ),
                case_level_memory_firewall_disposition=(
                    None if case_scan is None else case_scan.disposition
                ),
                case_level_memory_firewall_finding_count=(
                    0 if case_scan is None else case_scan.finding_count
                ),
                limitations=tuple(dict.fromkeys(limitations)),
            )
        )
    verdict_tuple = tuple(verdicts)
    issues = _build_issues(
        verdict_tuple,
        persisted,
        retrieved,
        matched_persisted,
        matched_retrieved,
        tuple(extra_issues),
    )
    downstream_verdicts = tuple(item for item in verdict_tuple if item.downstream_used)
    summary = LineageSummary(
        source_events=len(sources),
        candidates=len(candidates),
        persisted_candidates=sum(1 for item in verdict_tuple if item.persisted),
        retrieved_candidates=sum(1 for item in verdict_tuple if item.retrieved),
        downstream_used_candidates=sum(1 for item in verdict_tuple if item.downstream_used),
        candidate_level_verdicts=sum(
            1
            for item in verdict_tuple
            if item.scan_status == CandidateScanStatus.CANDIDATE_LEVEL
        ),
        case_level_only_candidates=sum(
            1
            for item in verdict_tuple
            if item.scan_status == CandidateScanStatus.CASE_LEVEL_ONLY
        ),
        unscanned_candidates=sum(
            1
            for item in verdict_tuple
            if item.scan_status == CandidateScanStatus.NOT_SCANNED
        ),
        unmatched_persisted_records=_unmatched_persisted_count(
            persisted,
            matched_persisted,
        ),
        unmatched_retrievals=_unmatched_retrieval_count(retrieved, matched_retrieved),
        scope_mismatches=sum(
            1
            for item in verdict_tuple
            if item.persisted_link_status == LineageLinkStatus.SCOPE_MISMATCH
            or item.retrieval_link_status == LineageLinkStatus.SCOPE_MISMATCH
        ),
        highest_any_candidate_disposition=_highest_disposition(verdict_tuple),
        highest_downstream_used_candidate_disposition=_highest_disposition(
            downstream_verdicts
        ),
        downstream_used_candidates_escalated=sum(
            1
            for item in downstream_verdicts
            if item.memory_firewall_disposition
            in (RecommendedDisposition.REVIEW, RecommendedDisposition.QUARANTINE)
        ),
        downstream_used_candidates_unscanned=sum(
            1
            for item in downstream_verdicts
            if item.scan_status != CandidateScanStatus.CANDIDATE_LEVEL
        ),
    )
    return LineageReport(
        lineage_version=LINEAGE_VERSION,
        provider=provider,
        provider_version=provider_version,
        summary=summary,
        candidate_verdicts=verdict_tuple,
        issues=issues,
        non_goals=(
            "no live provider adapter",
            "no write suppression",
            "no trusted ledger",
            "no hosted dashboard",
            "no verified provenance claim",
        ),
        metadata=_coerce_metadata(value.get("metadata", {})),
    )


def load_lineage_report(path: str) -> LineageReport:
    """Load and generate a lineage report from a JSON file."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise TypeError("lineage input must be a JSON object")
    return generate_lineage_report(payload)
