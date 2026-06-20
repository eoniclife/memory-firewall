"""Deterministic AMC-facing state analysis for memory events."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from agent_memory_contracts import (
    CandidateClaim as AMCCandidateClaim,
    EvidenceSpan as AMCEvidenceSpan,
    SourceRecord as AMCSourceRecord,
    make_candidate_id,
    make_source_id,
    make_span_id,
    sha256_hex,
    validate_candidate_bundle,
)

from .detectors import DetectorResult, run_detectors
from .models import (
    EVENT_ID_PREFIX,
    JSONScalar,
    MAX_TEXT_FIELD_CHARS,
    MemoryEvent,
    MemoryOperation,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    _canonical_json,
    _coerce_metadata,
    _freeze_metadata,
    _require_string,
)

ANALYSIS_VERSION = "mf-05"
ASSERTION_ID_PREFIX = "mfassert_v1_"
ANALYSIS_ID_PREFIX = "mfanalysis_v1_"
_PENDING_ASSERTION_ID = "_pending_assertion_id"
_STATE_ASSERTION_KEYS = frozenset(
    {
        "assertion_id",
        "subject",
        "predicate",
        "object_value",
        "object_hash_sha256",
        "object_redacted",
        "source_event_id",
        "source_authority",
        "asserted_at",
        "status",
        "supersedes",
        "metadata",
    }
)
_MEMORY_EVENT_ID_RE = re.compile(rf"^{EVENT_ID_PREFIX}[0-9a-f]{{32}}$")
_SECRET_LABEL_PATTERN = re.compile(
    r"\b(?P<label>api[_\-\s]?key|secret|password|passwd|token)\b"
    r"\s*[:=]\s*(?P<secret>[A-Za-z0-9_\-]{8,})",
    re.I,
)
_SECRET_LABEL_HINT_PATTERN = re.compile(
    r"\b(api[_\-\s]?key|secret|password|passwd|token)\b",
    re.I,
)
_OPENAI_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")
_CARD_LIKE_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


class StateAssertionStatus(str, Enum):
    """Local assertion lifecycle used before any trusted-state promotion."""

    CANDIDATE = "candidate"
    TRUSTED = "trusted"
    SUPERSEDED = "superseded"


class TrustedStateAction(str, Enum):
    """Deterministic analysis decision for later trusted-state handling."""

    CANDIDATE_ONLY = "candidate_only"
    REQUIRES_REDUCER_REVIEW = "requires_reducer_review"
    BLOCKED_LOW_AUTHORITY_CONTRADICTION = "blocked_low_authority_contradiction"


_AUTHORITY_RANK: Mapping[SourceAuthority, int] = MappingProxyType(
    {
        SourceAuthority.UNKNOWN: 0,
        SourceAuthority.UNTRUSTED: 0,
        SourceAuthority.USER_ASSERTED: 1,
        SourceAuthority.TOOL_OBSERVED: 2,
        SourceAuthority.SYSTEM: 3,
        SourceAuthority.SIGNED_RECORD: 4,
        SourceAuthority.HUMAN_APPROVED: 5,
    }
)
_LOW_AUTHORITY = frozenset(
    {
        SourceAuthority.UNKNOWN,
        SourceAuthority.UNTRUSTED,
        SourceAuthority.USER_ASSERTED,
    }
)
_SENSITIVE_CATEGORIES = frozenset({RiskCategory.SCOPE_OR_PRIVACY_VIOLATION})


def _sha256_text(value: str) -> str:
    return sha256_hex(value)


def _hash_json(value: Mapping[str, Any]) -> str:
    return _sha256_text(_canonical_json(value))


def _require_sha256(value: str, field_name: str) -> str:
    _require_string(value, field_name, allow_empty=False, max_chars=64)
    if len(value) != 64:
        raise ValueError(f"{field_name} must be 64 hex characters")
    int(value, 16)
    return value


def _require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be bool")
    return value


def _reject_unknown_fields(
    value: Mapping[str, Any], allowed: frozenset[str], label: str
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        joined = ", ".join(extra)
        raise ValueError(f"{label} contains unknown field(s): {joined}")


def _coerce_status(value: StateAssertionStatus | str) -> StateAssertionStatus:
    if isinstance(value, StateAssertionStatus):
        return value
    if not isinstance(value, str):
        raise TypeError("status must be a string")
    try:
        return StateAssertionStatus(value)
    except ValueError as exc:
        raise ValueError(f"unsupported status: {value}") from exc


def _coerce_action(value: TrustedStateAction | str) -> TrustedStateAction:
    if isinstance(value, TrustedStateAction):
        return value
    if not isinstance(value, str):
        raise TypeError("trusted_state_action must be a string")
    try:
        return TrustedStateAction(value)
    except ValueError as exc:
        raise ValueError(f"unsupported trusted_state_action: {value}") from exc


def _coerce_authority(value: SourceAuthority | str) -> SourceAuthority:
    if isinstance(value, SourceAuthority):
        return value
    if not isinstance(value, str):
        raise TypeError("source_authority must be a string")
    try:
        return SourceAuthority(value)
    except ValueError as exc:
        raise ValueError(f"unsupported source_authority: {value}") from exc


def _string_tuple(value: tuple[str, ...] | list[str], field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise TypeError(f"{field_name} must be a sequence of strings")
    coerced = tuple(value)
    if any(not isinstance(item, str) or not item for item in coerced):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return coerced


def _secret_value_ranges(text: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for match in _SECRET_LABEL_PATTERN.finditer(text):
        ranges.append(match.span("secret"))
    for pattern in (_OPENAI_KEY_PATTERN, _CARD_LIKE_PATTERN):
        for match in pattern.finditer(text):
            ranges.append(match.span())
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return tuple(merged)


def _contains_secret_like_text(value: str) -> bool:
    return bool(_secret_value_ranges(value))


def _contains_secret_label_hint(value: str) -> bool:
    return _SECRET_LABEL_HINT_PATTERN.search(value) is not None


def _redact_secret_like_text(value: str) -> str:
    ranges = _secret_value_ranges(value)
    if not ranges:
        return value
    chunks: list[str] = []
    cursor = 0
    for start, end in ranges:
        chunks.append(value[cursor:start])
        chunks.append("[redacted-secret]")
        cursor = end
    chunks.append(value[cursor:])
    redacted = "".join(chunks).strip()
    return redacted or "[redacted]"


def compute_state_assertion_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic id for a local state assertion."""

    digest = _hash_json(
        {
            "subject": value["subject"],
            "predicate": value["predicate"],
            "object_hash_sha256": value["object_hash_sha256"],
            "source_event_id": value["source_event_id"],
        }
    )
    return f"{ASSERTION_ID_PREFIX}{digest[:32]}"


def compute_state_analysis_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic id for a state analysis result."""

    digest = _hash_json(
        {
            "event_id": value["event_id"],
            "assertion_id": value["assertion"]["assertion_id"],
            "finding_ids": value["finding_ids"],
            "contradiction_ids": [
                item["existing_assertion_id"] for item in value["contradictions"]
            ],
            "supersession_candidate_ids": value["supersession_candidate_ids"],
            "trusted_state_action": value["trusted_state_action"],
        }
    )
    return f"{ANALYSIS_ID_PREFIX}{digest[:32]}"


def _metadata_string(
    metadata: Mapping[str, JSONScalar], key: str, default: str
) -> str:
    value = metadata.get(key)
    if isinstance(value, str) and value:
        return value
    return default


def _state_subject(event: MemoryEvent) -> str:
    default = f"{event.user_or_tenant_scope}:{event.target_namespace}"
    return _redact_secret_like_text(
        _metadata_string(event.metadata, "state_subject", default)
    )


def _state_predicate(event: MemoryEvent) -> str:
    return _redact_secret_like_text(
        _metadata_string(event.metadata, "state_predicate", "proposed_memory")
    )


def _state_object(event: MemoryEvent) -> str:
    default = event.proposed_memory or event.raw_or_redacted_content or "[empty event]"
    return _metadata_string(event.metadata, "state_object", default)


def _redacted_object(event: MemoryEvent) -> str:
    return f"[redacted by memory-firewall; see event {event.event_id}]"


def _safe_actor(event: MemoryEvent) -> str | None:
    if _contains_secret_like_text(event.actor):
        return None
    return event.actor


def _safe_metadata_value(value: str) -> str:
    return _redact_secret_like_text(value)


@dataclass(frozen=True, slots=True)
class AuthorityAssessment:
    """Declared source authority plus the local trust-boundary interpretation."""

    source_authority: SourceAuthority
    rank: int
    can_enter_candidate_plane: bool
    can_skip_reducer_review: bool
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_authority, SourceAuthority):
            raise TypeError("source_authority must be a SourceAuthority")
        if self.rank != _AUTHORITY_RANK[self.source_authority]:
            raise ValueError("rank must match source_authority")
        if not isinstance(self.can_enter_candidate_plane, bool):
            raise TypeError("can_enter_candidate_plane must be bool")
        if not isinstance(self.can_skip_reducer_review, bool):
            raise TypeError("can_skip_reducer_review must be bool")
        object.__setattr__(
            self, "reason_codes", _string_tuple(self.reason_codes, "reason_codes")
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable authority assessment."""

        return {
            "source_authority": self.source_authority.value,
            "rank": self.rank,
            "can_enter_candidate_plane": self.can_enter_candidate_plane,
            "can_skip_reducer_review": self.can_skip_reducer_review,
            "reason_codes": list(self.reason_codes),
        }


def assess_source_authority(source_authority: SourceAuthority) -> AuthorityAssessment:
    """Return deterministic source-authority handling for MF-05."""

    reason_codes = ["authority:declared", "trusted_state:requires_reducer_review"]
    if source_authority in _LOW_AUTHORITY:
        reason_codes.append("authority:low")
    else:
        reason_codes.append("authority:review_eligible")
    return AuthorityAssessment(
        source_authority=source_authority,
        rank=_AUTHORITY_RANK[source_authority],
        can_enter_candidate_plane=True,
        can_skip_reducer_review=False,
        reason_codes=tuple(reason_codes),
    )


@dataclass(frozen=True, slots=True)
class MemoryStateAssertion:
    """A deterministic local assertion extracted from one MemoryEvent."""

    assertion_id: str
    subject: str
    predicate: str
    object_value: str
    object_hash_sha256: str
    object_redacted: bool
    source_event_id: str
    source_authority: SourceAuthority
    asserted_at: str
    status: StateAssertionStatus = StateAssertionStatus.CANDIDATE
    supersedes: tuple[str, ...] = ()
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        _require_string(
            self.assertion_id,
            "assertion_id",
            allow_empty=False,
            max_chars=96,
        )
        _require_string(
            self.subject,
            "subject",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.predicate,
            "predicate",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.object_value,
            "object_value",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_sha256(self.object_hash_sha256, "object_hash_sha256")
        if not isinstance(self.object_redacted, bool):
            raise TypeError("object_redacted must be bool")
        _require_string(
            self.source_event_id,
            "source_event_id",
            allow_empty=False,
            max_chars=96,
        )
        if _MEMORY_EVENT_ID_RE.fullmatch(self.source_event_id) is None:
            raise ValueError("source_event_id must be a MemoryEvent id")
        object.__setattr__(
            self, "source_authority", _coerce_authority(self.source_authority)
        )
        _require_string(
            self.asserted_at,
            "asserted_at",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        object.__setattr__(self, "status", _coerce_status(self.status))
        object.__setattr__(
            self, "supersedes", _string_tuple(self.supersedes, "supersedes")
        )
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))
        if self.assertion_id != _PENDING_ASSERTION_ID:
            expected = compute_state_assertion_id(self.to_dict())
            if self.assertion_id != expected:
                raise ValueError(f"assertion_id mismatch: expected {expected}")

    @property
    def conflict_key(self) -> tuple[str, str]:
        """Return the local key used for contradiction checks."""

        return (self.subject, self.predicate)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable assertion."""

        return {
            "assertion_id": self.assertion_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "object_value": self.object_value,
            "object_hash_sha256": self.object_hash_sha256,
            "object_redacted": self.object_redacted,
            "source_event_id": self.source_event_id,
            "source_authority": self.source_authority.value,
            "asserted_at": self.asserted_at,
            "status": self.status.value,
            "supersedes": list(self.supersedes),
            "metadata": _coerce_metadata({} if self.metadata is None else self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryStateAssertion":
        """Build an assertion from JSON-like data."""

        _reject_unknown_fields(value, _STATE_ASSERTION_KEYS, "MemoryStateAssertion")
        metadata_value = value.get("metadata", {})
        if not isinstance(metadata_value, Mapping):
            raise TypeError("metadata must be a mapping")
        return cls(
            assertion_id=_require_string(
                value["assertion_id"],
                "assertion_id",
                allow_empty=False,
                max_chars=96,
            ),
            subject=_require_string(
                value["subject"],
                "subject",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            predicate=_require_string(
                value["predicate"],
                "predicate",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            object_value=_require_string(
                value["object_value"],
                "object_value",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            object_hash_sha256=_require_sha256(
                value["object_hash_sha256"],
                "object_hash_sha256",
            ),
            object_redacted=_require_bool(value["object_redacted"], "object_redacted"),
            source_event_id=_require_string(
                value["source_event_id"],
                "source_event_id",
                allow_empty=False,
                max_chars=96,
            ),
            source_authority=_coerce_authority(value["source_authority"]),
            asserted_at=_require_string(
                value["asserted_at"],
                "asserted_at",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            status=_coerce_status(value["status"]),
            supersedes=_string_tuple(value.get("supersedes", ()), "supersedes"),
            metadata=_coerce_metadata(metadata_value),
        )

    @classmethod
    def from_event(
        cls,
        event: MemoryEvent,
        *,
        redact_object: bool,
        status: StateAssertionStatus = StateAssertionStatus.CANDIDATE,
    ) -> "MemoryStateAssertion":
        """Create a deterministic local assertion from a MemoryEvent."""

        raw_object = _state_object(event)
        subject = _state_subject(event)
        predicate = _state_predicate(event)
        object_redacted = (
            redact_object
            or _contains_secret_like_text(raw_object)
            or _contains_secret_label_hint(subject)
            or _contains_secret_label_hint(predicate)
        )
        object_value = (
            _redacted_object(event)
            if object_redacted
            else _redact_secret_like_text(raw_object)
        )
        pending = cls(
            assertion_id=_PENDING_ASSERTION_ID,
            subject=subject,
            predicate=predicate,
            object_value=object_value,
            object_hash_sha256=_sha256_text(raw_object),
            object_redacted=object_redacted,
            source_event_id=event.event_id,
            source_authority=event.source_authority,
            asserted_at=event.timestamp,
            status=status,
            metadata={
                "memory_firewall_target_namespace": _safe_metadata_value(
                    event.target_namespace
                ),
                "memory_firewall_operation": event.operation.value,
            },
        )
        return cls.from_dict(
            {**pending.to_dict(), "assertion_id": compute_state_assertion_id(pending.to_dict())}
        )


@dataclass(frozen=True, slots=True)
class StateContradiction:
    """A deterministic contradiction between an existing assertion and a candidate."""

    existing_assertion_id: str
    candidate_assertion_id: str
    subject: str
    predicate: str
    existing_object_hash_sha256: str
    candidate_object_hash_sha256: str
    existing_source_authority: SourceAuthority
    candidate_source_authority: SourceAuthority
    existing_status: StateAssertionStatus

    def __post_init__(self) -> None:
        _require_string(
            self.existing_assertion_id,
            "existing_assertion_id",
            allow_empty=False,
            max_chars=96,
        )
        _require_string(
            self.candidate_assertion_id,
            "candidate_assertion_id",
            allow_empty=False,
            max_chars=96,
        )
        _require_string(
            self.subject,
            "subject",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_string(
            self.predicate,
            "predicate",
            allow_empty=False,
            max_chars=MAX_TEXT_FIELD_CHARS,
        )
        _require_sha256(self.existing_object_hash_sha256, "existing_object_hash_sha256")
        _require_sha256(self.candidate_object_hash_sha256, "candidate_object_hash_sha256")
        object.__setattr__(
            self,
            "existing_source_authority",
            _coerce_authority(self.existing_source_authority),
        )
        object.__setattr__(
            self,
            "candidate_source_authority",
            _coerce_authority(self.candidate_source_authority),
        )
        object.__setattr__(
            self, "existing_status", _coerce_status(self.existing_status)
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable contradiction."""

        return {
            "existing_assertion_id": self.existing_assertion_id,
            "candidate_assertion_id": self.candidate_assertion_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "existing_object_hash_sha256": self.existing_object_hash_sha256,
            "candidate_object_hash_sha256": self.candidate_object_hash_sha256,
            "existing_source_authority": self.existing_source_authority.value,
            "candidate_source_authority": self.candidate_source_authority.value,
            "existing_status": self.existing_status.value,
        }


@dataclass(frozen=True, slots=True)
class AMCMapping:
    """Validated AMC evidence and candidate records derived from one event."""

    source_record: Mapping[str, Any]
    evidence_span: Mapping[str, Any]
    candidate_claim: Mapping[str, Any]

    def __post_init__(self) -> None:
        source_record = dict(self.source_record)
        evidence_span = dict(self.evidence_span)
        candidate_claim = dict(self.candidate_claim)
        AMCSourceRecord.from_dict(source_record)
        AMCEvidenceSpan.from_dict(evidence_span)
        AMCCandidateClaim.from_dict(candidate_claim)
        validate_candidate_bundle(
            [source_record],
            [],
            [evidence_span],
            [candidate_claim],
        )
        object.__setattr__(self, "source_record", MappingProxyType(source_record))
        object.__setattr__(self, "evidence_span", MappingProxyType(evidence_span))
        object.__setattr__(self, "candidate_claim", MappingProxyType(candidate_claim))

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable AMC records."""

        return {
            "source_record": dict(self.source_record),
            "evidence_span": dict(self.evidence_span),
            "candidate_claim": dict(self.candidate_claim),
        }


@dataclass(frozen=True, slots=True)
class StateAnalysisResult:
    """Deterministic output for one MF-05 state analysis run."""

    analysis_id: str
    analysis_version: str
    event_id: str
    assertion: MemoryStateAssertion
    authority_assessment: AuthorityAssessment
    contradictions: tuple[StateContradiction, ...]
    supersession_candidate_ids: tuple[str, ...]
    trusted_state_action: TrustedStateAction
    reason_codes: tuple[str, ...]
    limitations: tuple[str, ...]
    finding_ids: tuple[str, ...]
    amc_mapping: AMCMapping

    def __post_init__(self) -> None:
        _require_string(
            self.analysis_id,
            "analysis_id",
            allow_empty=False,
            max_chars=96,
        )
        if self.analysis_version != ANALYSIS_VERSION:
            raise ValueError(f"analysis_version must be {ANALYSIS_VERSION}")
        _require_string(self.event_id, "event_id", allow_empty=False, max_chars=96)
        if not isinstance(self.assertion, MemoryStateAssertion):
            raise TypeError("assertion must be a MemoryStateAssertion")
        if self.event_id != self.assertion.source_event_id:
            raise ValueError("event_id must match assertion.source_event_id")
        if not isinstance(self.authority_assessment, AuthorityAssessment):
            raise TypeError("authority_assessment must be an AuthorityAssessment")
        if any(
            not isinstance(item, StateContradiction) for item in self.contradictions
        ):
            raise TypeError("contradictions must contain StateContradiction objects")
        object.__setattr__(
            self,
            "supersession_candidate_ids",
            _string_tuple(
                self.supersession_candidate_ids,
                "supersession_candidate_ids",
            ),
        )
        object.__setattr__(
            self, "trusted_state_action", _coerce_action(self.trusted_state_action)
        )
        object.__setattr__(
            self, "reason_codes", _string_tuple(self.reason_codes, "reason_codes")
        )
        object.__setattr__(
            self, "limitations", _string_tuple(self.limitations, "limitations")
        )
        object.__setattr__(
            self, "finding_ids", _string_tuple(self.finding_ids, "finding_ids")
        )
        if not isinstance(self.amc_mapping, AMCMapping):
            raise TypeError("amc_mapping must be an AMCMapping")
        expected = compute_state_analysis_id(self.to_dict())
        if self.analysis_id != expected:
            raise ValueError(f"analysis_id mismatch: expected {expected}")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable analysis result."""

        return {
            "analysis_id": self.analysis_id,
            "analysis_version": self.analysis_version,
            "event_id": self.event_id,
            "assertion": self.assertion.to_dict(),
            "authority_assessment": self.authority_assessment.to_dict(),
            "contradictions": [item.to_dict() for item in self.contradictions],
            "supersession_candidate_ids": list(self.supersession_candidate_ids),
            "trusted_state_action": self.trusted_state_action.value,
            "reason_codes": list(self.reason_codes),
            "limitations": list(self.limitations),
            "finding_ids": list(self.finding_ids),
            "amc_mapping": self.amc_mapping.to_dict(),
        }


def _requires_redaction(findings: tuple[Any, ...]) -> bool:
    return any(
        getattr(finding, "risk_category", None) in _SENSITIVE_CATEGORIES
        or getattr(finding, "detector_name", "") == "secret-pattern-v1"
        for finding in findings
    )


def _high_impact(findings: tuple[Any, ...]) -> bool:
    return any(getattr(finding, "severity", None) == RiskSeverity.HIGH_IMPACT for finding in findings)


def _contradictions(
    candidate: MemoryStateAssertion,
    existing_assertions: tuple[MemoryStateAssertion, ...],
) -> tuple[StateContradiction, ...]:
    items: list[StateContradiction] = []
    for existing in existing_assertions:
        if existing.conflict_key != candidate.conflict_key:
            continue
        if existing.object_hash_sha256 == candidate.object_hash_sha256:
            continue
        items.append(
            StateContradiction(
                existing_assertion_id=existing.assertion_id,
                candidate_assertion_id=candidate.assertion_id,
                subject=candidate.subject,
                predicate=candidate.predicate,
                existing_object_hash_sha256=existing.object_hash_sha256,
                candidate_object_hash_sha256=candidate.object_hash_sha256,
                existing_source_authority=existing.source_authority,
                candidate_source_authority=candidate.source_authority,
                existing_status=existing.status,
            )
        )
    return tuple(
        sorted(items, key=lambda item: (item.subject, item.predicate, item.existing_assertion_id))
    )


def _supersession_candidates(
    event: MemoryEvent,
    candidate: MemoryStateAssertion,
    contradictions: tuple[StateContradiction, ...],
) -> tuple[str, ...]:
    if event.operation not in {MemoryOperation.UPDATE, MemoryOperation.UPSERT}:
        return ()
    candidate_rank = _AUTHORITY_RANK[candidate.source_authority]
    ids = [
        item.existing_assertion_id
        for item in contradictions
        if candidate_rank > _AUTHORITY_RANK[item.existing_source_authority]
        and candidate.source_authority not in _LOW_AUTHORITY
    ]
    return tuple(sorted(ids))


def _trusted_state_action(
    event: MemoryEvent,
    contradictions: tuple[StateContradiction, ...],
    findings: tuple[Any, ...],
) -> TrustedStateAction:
    if event.source_authority in _LOW_AUTHORITY and contradictions:
        return TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
    if contradictions or findings:
        return TrustedStateAction.REQUIRES_REDUCER_REVIEW
    return TrustedStateAction.CANDIDATE_ONLY


def _reason_codes(
    action: TrustedStateAction,
    contradictions: tuple[StateContradiction, ...],
    findings: tuple[Any, ...],
) -> tuple[str, ...]:
    reasons = ["state:no_silent_promotion", f"action:{action.value}"]
    if contradictions:
        reasons.append("state:contradiction")
    if action == TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION:
        reasons.append("authority:low_authority_contradiction")
    for category in sorted(
        {
            getattr(finding, "risk_category").value
            for finding in findings
            if hasattr(getattr(finding, "risk_category", None), "value")
        }
    ):
        reasons.append(f"finding:{category}")
    return tuple(reasons)


def _privacy_class(redacted: bool, findings: tuple[Any, ...]) -> str:
    if redacted:
        return "sensitive"
    if _high_impact(findings):
        return "private"
    return "internal"


def _risk_class(
    action: TrustedStateAction, findings: tuple[Any, ...]
) -> str:
    if action == TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION:
        return "high"
    if _high_impact(findings):
        return "high"
    if findings:
        return "medium"
    return "low"


def _candidate_status(action: TrustedStateAction, findings: tuple[Any, ...]) -> str:
    if action == TrustedStateAction.CANDIDATE_ONLY and not findings:
        return "candidate"
    return "needs_review"


def _candidate_confidence(event: MemoryEvent) -> str:
    if event.source_authority in _LOW_AUTHORITY:
        return "low"
    return "medium"


def _build_amc_mapping(
    event: MemoryEvent,
    assertion: MemoryStateAssertion,
    findings: tuple[Any, ...],
    action: TrustedStateAction,
) -> AMCMapping:
    redacted = assertion.object_redacted
    privacy_class = _privacy_class(redacted, findings)
    event_payload = event.to_dict()
    event_hash = _hash_json(event_payload)
    raw_ref = {"kind": "content_hash_only", "value": event.event_id}
    source_id = make_source_id("other", raw_ref, event_hash)
    safe_actor = _safe_actor(event)
    source_record: dict[str, Any] = {
        "id": source_id,
        "schema_version": "1.0.0",
        "source_type": "other",
        "title": f"Memory Firewall event {event.event_id}",
        "origin_uri": None,
        "raw_ref": raw_ref,
        "content_hash_sha256": event_hash,
        "captured_at": event.timestamp,
        "observed_at": event.timestamp,
        "author_or_sender": safe_actor,
        "participants": [] if safe_actor is None else [safe_actor],
        "privacy_class": privacy_class,
        "custody_status": "redacted" if redacted else "synthetic",
        "parser_version": ANALYSIS_VERSION,
        "metadata": {
            "memory_firewall_event_id": event.event_id,
            "target_namespace": _safe_metadata_value(event.target_namespace),
            "actor_redacted": safe_actor is None,
        },
    }

    locator_value = f"memory-event/{event.event_id}/proposed_memory"
    span_id = make_span_id(source_id, "synthetic_locator", locator_value)
    excerpt = None if redacted else assertion.object_value[:512]
    evidence_span: dict[str, Any] = {
        "id": span_id,
        "schema_version": "1.0.0",
        "source_id": source_id,
        "episode_id": None,
        "locator": {"kind": "synthetic_locator", "value": locator_value},
        "text_excerpt": excerpt,
        "excerpt_policy": "none" if excerpt is None else "short_quote_allowed",
        "span_hash_sha256": assertion.object_hash_sha256,
        "privacy_class": privacy_class,
        "metadata": {"memory_firewall_assertion_id": assertion.assertion_id},
    }

    risk_categories = sorted(
        {
            getattr(finding, "risk_category").value
            for finding in findings
            if hasattr(getattr(finding, "risk_category", None), "value")
        }
    )
    semantic_payload = {
        "subject": assertion.subject,
        "predicate": assertion.predicate,
        "object": assertion.object_value,
        "claim_text": assertion.object_value,
        "claim_scope": "source_local",
        "temporal_hint": {
            "observed_at": event.timestamp,
            "asserted_at": event.timestamp,
            "valid_from_hint": None,
            "valid_until_hint": None,
        },
    }
    candidate_id = make_candidate_id("claim", [span_id], semantic_payload)
    candidate_claim: dict[str, Any] = {
        "id": candidate_id,
        "schema_version": "1.0.0",
        "candidate_type": "claim",
        "source_record_ids": [source_id],
        "episode_record_ids": [],
        "evidence_span_ids": [span_id],
        "natural_language_summary": (
            "Memory event converted to an untrusted candidate claim for reducer review."
        ),
        "extracted_by": {
            "agent": "memory-firewall",
            "model": "deterministic",
            "tool": "analyze_memory_state",
            "prompt_ref": None,
        },
        "extracted_at": event.timestamp,
        "confidence": _candidate_confidence(event),
        "risk_class": _risk_class(action, findings),
        "status": _candidate_status(action, findings),
        "review": {
            "reviewed_by": None,
            "reviewed_at": None,
            "review_notes": None,
        },
        "metadata": {
            "memory_firewall_event_id": event.event_id,
            "memory_firewall_assertion_id": assertion.assertion_id,
            "memory_firewall_analysis_version": ANALYSIS_VERSION,
            "trusted_state_action": action.value,
            "source_authority": event.source_authority.value,
            "risk_categories": ",".join(risk_categories),
        },
        **semantic_payload,
    }
    return AMCMapping(
        source_record=source_record,
        evidence_span=evidence_span,
        candidate_claim=candidate_claim,
    )


def analyze_memory_state(
    event: MemoryEvent,
    *,
    detector_result: DetectorResult | None = None,
    existing_assertions: tuple[MemoryStateAssertion, ...] = (),
) -> StateAnalysisResult:
    """Analyze one event against optional existing local state assertions."""

    active_detector_result = detector_result or run_detectors(event)
    if active_detector_result.event_id != event.event_id:
        raise ValueError("detector_result event_id must match event.event_id")
    findings = active_detector_result.findings
    assertion = MemoryStateAssertion.from_event(
        event,
        redact_object=_requires_redaction(findings),
    )
    contradictions = _contradictions(assertion, existing_assertions)
    action = _trusted_state_action(event, contradictions, findings)
    supersession_candidate_ids = _supersession_candidates(
        event,
        assertion,
        contradictions,
    )
    amc_mapping = _build_amc_mapping(event, assertion, findings, action)
    payload: dict[str, Any] = {
        "event_id": event.event_id,
        "assertion": assertion.to_dict(),
        "contradictions": [item.to_dict() for item in contradictions],
        "supersession_candidate_ids": list(supersession_candidate_ids),
        "trusted_state_action": action.value,
        "finding_ids": [finding.finding_id for finding in findings],
    }
    analysis_id = compute_state_analysis_id(payload)
    return StateAnalysisResult(
        analysis_id=analysis_id,
        analysis_version=ANALYSIS_VERSION,
        event_id=event.event_id,
        assertion=assertion,
        authority_assessment=assess_source_authority(event.source_authority),
        contradictions=contradictions,
        supersession_candidate_ids=supersession_candidate_ids,
        trusted_state_action=action,
        reason_codes=_reason_codes(action, contradictions, findings),
        limitations=(
            "Deterministic local analysis only.",
            "Does not determine objective truth.",
            "Does not promote trusted memory or approve state.",
            "AMC records are candidate/evidence previews for reducer review.",
        ),
        finding_ids=tuple(finding.finding_id for finding in findings),
        amc_mapping=amc_mapping,
    )
