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
        "persisted_memories",
        "retrieved_memories",
        "metadata",
    }
)


class LineageLinkStatus(str, Enum):
    """How confidently a candidate was linked across provider stages."""

    EXACT_PROVIDER_ID = "exact_provider_id"
    EXACT_CONTENT_DIGEST = "exact_content_digest"
    NOT_PERSISTED = "not_persisted"
    NOT_RETRIEVED = "not_retrieved"
    SCOPE_MISMATCH = "scope_mismatch"


class CandidateScanStatus(str, Enum):
    """Whether Memory Firewall has a candidate-level scan verdict."""

    CANDIDATE_LEVEL = "candidate_level"
    CASE_LEVEL_ONLY = "case_level_only"
    NOT_SCANNED = "not_scanned"


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
    link_status: LineageLinkStatus
    persisted: bool
    retrieved: bool
    downstream_used: bool
    scan_status: CandidateScanStatus
    memory_firewall_event_id: str | None
    memory_firewall_disposition: RecommendedDisposition | None
    memory_firewall_finding_count: int
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
        if not isinstance(self.link_status, LineageLinkStatus):
            raise TypeError("link_status must be a LineageLinkStatus")
        for field_name in ("persisted", "retrieved", "downstream_used"):
            _require_bool(getattr(self, field_name), field_name)
        if not isinstance(self.scan_status, CandidateScanStatus):
            raise TypeError("scan_status must be a CandidateScanStatus")
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
            "link_status": self.link_status.value,
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
    highest_candidate_disposition: RecommendedDisposition

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
        ):
            object.__setattr__(
                self,
                field_name,
                _require_non_negative_int(getattr(self, field_name), field_name),
            )
        if not isinstance(self.highest_candidate_disposition, RecommendedDisposition):
            raise TypeError(
                "highest_candidate_disposition must be a RecommendedDisposition"
            )

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
            "highest_candidate_disposition": self.highest_candidate_disposition.value,
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
            PersistedMemoryRecord.from_dict(item)
            for item in payload["persisted_memories"]
        ),
        tuple(
            RetrievedMemoryRecord.from_dict(item)
            for item in payload["retrieved_memories"]
        ),
    )


def _record_key(record: PersistedMemoryRecord | RetrievedMemoryRecord) -> tuple[str, str] | None:
    if record.provider_memory_id is None:
        return None
    return (record.lineage_id, record.provider_memory_id)


def _digest_key(record: PersistedMemoryRecord | RetrievedMemoryRecord) -> tuple[str, str]:
    return (record.lineage_id, record.content_digest)


def _match_persisted(
    candidate: ExtractedCandidateRecord,
    persisted_by_provider: Mapping[tuple[str, str], PersistedMemoryRecord],
    persisted_by_digest: Mapping[tuple[str, str], PersistedMemoryRecord],
) -> tuple[PersistedMemoryRecord | None, LineageLinkStatus, tuple[str, ...]]:
    limitations: list[str] = []
    if candidate.provider_memory_id is not None:
        provider_match = persisted_by_provider.get(
            (candidate.lineage_id, candidate.provider_memory_id)
        )
        if provider_match is not None:
            if provider_match.scope != candidate.scope:
                limitations.append("provider id matched but persisted scope differs")
                return provider_match, LineageLinkStatus.SCOPE_MISMATCH, tuple(limitations)
            return provider_match, LineageLinkStatus.EXACT_PROVIDER_ID, ()
    digest_match = persisted_by_digest.get((candidate.lineage_id, candidate.content_digest))
    if digest_match is not None:
        if digest_match.scope != candidate.scope:
            limitations.append("content digest matched but persisted scope differs")
            return digest_match, LineageLinkStatus.SCOPE_MISMATCH, tuple(limitations)
        limitations.append("matched by content digest because provider memory id was missing")
        return digest_match, LineageLinkStatus.EXACT_CONTENT_DIGEST, tuple(limitations)
    return None, LineageLinkStatus.NOT_PERSISTED, ("candidate was not linked to persisted memory",)


def _match_retrieved(
    candidate: ExtractedCandidateRecord,
    persisted: PersistedMemoryRecord | None,
    retrieved_by_provider: Mapping[tuple[str, str], RetrievedMemoryRecord],
    retrieved_by_persisted_id: Mapping[str, RetrievedMemoryRecord],
    retrieved_by_digest: Mapping[tuple[str, str], RetrievedMemoryRecord],
) -> tuple[RetrievedMemoryRecord | None, tuple[str, ...]]:
    limitations: list[str] = []
    if candidate.provider_memory_id is not None:
        provider_match = retrieved_by_provider.get(
            (candidate.lineage_id, candidate.provider_memory_id)
        )
        if provider_match is not None:
            if provider_match.scope != candidate.scope:
                limitations.append("provider id matched but retrieval scope differs")
            return provider_match, tuple(limitations)
    if persisted is not None:
        persisted_match = retrieved_by_persisted_id.get(persisted.persisted_record_id)
        if persisted_match is not None:
            if persisted_match.scope != candidate.scope:
                limitations.append("persisted id matched but retrieval scope differs")
            return persisted_match, tuple(limitations)
    digest_match = retrieved_by_digest.get((candidate.lineage_id, candidate.content_digest))
    if digest_match is not None:
        if digest_match.scope != candidate.scope:
            limitations.append("content digest matched but retrieval scope differs")
        limitations.append("retrieval matched by content digest")
        return digest_match, tuple(limitations)
    return None, ("candidate was not linked to retrieved memory",)


def _scan_status(candidate: ExtractedCandidateRecord) -> CandidateScanStatus:
    raw_status = candidate.metadata.get("scan_status")
    if raw_status == CandidateScanStatus.CASE_LEVEL_ONLY.value:
        return CandidateScanStatus.CASE_LEVEL_ONLY
    if candidate.memory_firewall_event_id is None:
        return CandidateScanStatus.NOT_SCANNED
    return CandidateScanStatus.CANDIDATE_LEVEL


def _unmatched_persisted_count(
    persisted: tuple[PersistedMemoryRecord, ...],
    matched_ids: set[str],
) -> int:
    return sum(1 for item in persisted if item.persisted_record_id not in matched_ids)


def _unmatched_retrieval_count(
    retrieved: tuple[RetrievedMemoryRecord, ...],
    matched_ids: set[str],
) -> int:
    return sum(1 for item in retrieved if item.retrieval_event_id not in matched_ids)


def _build_issues(
    verdicts: tuple[CandidateLineageVerdict, ...],
    persisted: tuple[PersistedMemoryRecord, ...],
    retrieved: tuple[RetrievedMemoryRecord, ...],
    matched_persisted: set[str],
    matched_retrieved: set[str],
) -> tuple[LineageIssue, ...]:
    issues: list[LineageIssue] = []
    for verdict in verdicts:
        if verdict.link_status == LineageLinkStatus.SCOPE_MISMATCH:
            issues.append(
                LineageIssue(
                    code="scope_mismatch",
                    message="candidate matched a provider record from a different scope",
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
        if persisted_record.persisted_record_id not in matched_persisted:
            issues.append(
                LineageIssue(
                    code="unmatched_persisted_record",
                    message="persisted provider record was not linked to an extracted candidate",
                    provider_memory_id=persisted_record.provider_memory_id,
                    persisted_record_id=persisted_record.persisted_record_id,
                )
            )
    for retrieved_record in retrieved:
        if retrieved_record.retrieval_event_id not in matched_retrieved:
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
    sources, candidates, persisted, retrieved = _records_from_payload(value)
    sources_by_id = {item.source_event_id: item for item in sources}
    persisted_by_provider = {
        key: item for item in persisted if (key := _record_key(item)) is not None
    }
    persisted_by_digest = {_digest_key(item): item for item in persisted}
    retrieved_by_provider = {
        key: item for item in retrieved if (key := _record_key(item)) is not None
    }
    retrieved_by_persisted_id = {
        item.persisted_record_id: item
        for item in retrieved
        if item.persisted_record_id is not None
    }
    retrieved_by_digest = {_digest_key(item): item for item in retrieved}
    verdicts: list[CandidateLineageVerdict] = []
    matched_persisted: set[str] = set()
    matched_retrieved: set[str] = set()
    for candidate in candidates:
        source = sources_by_id.get(candidate.source_event_id)
        persisted_match, link_status, persisted_limitations = _match_persisted(
            candidate,
            persisted_by_provider,
            persisted_by_digest,
        )
        retrieved_match, retrieval_limitations = _match_retrieved(
            candidate,
            persisted_match,
            retrieved_by_provider,
            retrieved_by_persisted_id,
            retrieved_by_digest,
        )
        if persisted_match is not None:
            matched_persisted.add(persisted_match.persisted_record_id)
        if retrieved_match is not None:
            matched_retrieved.add(retrieved_match.retrieval_event_id)
        limitations = list(persisted_limitations)
        limitations.extend(retrieval_limitations)
        if source is None:
            limitations.append("source event was not present in lineage packet")
        scan_status = _scan_status(candidate)
        if scan_status == CandidateScanStatus.CASE_LEVEL_ONLY:
            limitations.append("Memory Firewall verdict is case-level, not candidate-level")
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
                link_status=link_status,
                persisted=persisted_match is not None,
                retrieved=retrieved_match is not None,
                downstream_used=False if retrieved_match is None else retrieved_match.downstream_used,
                scan_status=scan_status,
                memory_firewall_event_id=candidate.memory_firewall_event_id,
                memory_firewall_disposition=candidate.memory_firewall_disposition,
                memory_firewall_finding_count=candidate.memory_firewall_finding_count,
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
    )
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
            if item.link_status == LineageLinkStatus.SCOPE_MISMATCH
        ),
        highest_candidate_disposition=_highest_disposition(verdict_tuple),
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
