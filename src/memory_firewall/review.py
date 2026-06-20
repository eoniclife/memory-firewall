"""Local review queue, override receipts, and trusted-read previews."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .analysis import (
    MemoryStateAssertion,
    TrustedStateAction,
    _redact_secret_like_text,
)
from .models import (
    JSONScalar,
    MAX_TEXT_FIELD_CHARS,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    _canonical_json,
    _coerce_enum,
    _coerce_metadata,
    _freeze_metadata,
    _require_int,
    _reject_unknown_fields,
    _require_string,
)
from .scan import SCAN_VERSION, ScanEventLevel, ScanEventResult, ScanResult

REVIEW_VERSION = "mf-07"
REVIEW_ITEM_ID_PREFIX = "mfrevitem_v1_"
OVERRIDE_RECEIPT_ID_PREFIX = "mfreceipt_v1_"
TRUSTED_READ_PREVIEW_STATUS = "allowed_preview_only"
DEFAULT_REVIEWER = "local-reviewer"
MAX_REASON_CHARS = 2048
MAX_REVIEWER_CHARS = 256

_REVIEW_FINDING_SUMMARY_KEYS = frozenset(
    {
        "finding_id",
        "risk_category",
        "severity",
        "recommended_disposition",
        "detector_name",
        "explanation",
        "limitations",
    }
)
_REVIEW_ITEM_KEYS = frozenset(
    {
        "item_id",
        "item_hash_sha256",
        "review_version",
        "source",
        "line_number",
        "event_id",
        "level",
        "highest_disposition",
        "finding_count",
        "contradiction_count",
        "analysis_id",
        "trusted_state_action",
        "assertion",
        "reason_codes",
        "finding_summaries",
        "status",
        "receipt_id",
        "metadata",
    }
)
_OVERRIDE_RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "receipt_version",
        "item_id",
        "item_hash_sha256",
        "decision",
        "reason",
        "reviewer",
        "event_id",
        "assertion_id",
        "finding_ids",
        "metadata",
    }
)
_REVIEW_QUEUE_KEYS = frozenset(
    {"review_version", "items", "receipts", "metadata"}
)


class ReviewItemStatus(str, Enum):
    """Lifecycle of a local review item."""

    PENDING = "pending"
    ALLOWED = "allowed"
    REJECTED = "rejected"


class OverrideDecision(str, Enum):
    """Explicit local decision for a review item."""

    ALLOW = "allow"
    REJECT = "reject"


def _sha256_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_sha256(value: str, field_name: str) -> str:
    _require_string(value, field_name, allow_empty=False, max_chars=64)
    if len(value) != 64:
        raise ValueError(f"{field_name} must be 64 hex characters")
    int(value, 16)
    return value


def _string_tuple(value: tuple[str, ...] | list[str], field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise TypeError(f"{field_name} must be a sequence of strings")
    coerced = tuple(value)
    if any(not isinstance(item, str) or not item for item in coerced):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return coerced


def _clean_reason_text(value: str, field_name: str, *, max_chars: int) -> str:
    cleaned = _redact_secret_like_text(
        _require_string(
            value.strip(),
            field_name,
            allow_empty=False,
            max_chars=max_chars,
        )
    )
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    return cleaned


def _metadata_dict(
    value: Mapping[str, JSONScalar] | None,
) -> dict[str, JSONScalar]:
    return _coerce_metadata({} if value is None else value)


def compute_review_item_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic id for a local review item."""

    digest = _sha256_json(
        {
            "source": value["source"],
            "line_number": value["line_number"],
            "event_id": value["event_id"],
            "analysis_id": value["analysis_id"],
            "assertion_id": value["assertion"]["assertion_id"],
            "trusted_state_action": value["trusted_state_action"],
            "finding_ids": [
                item["finding_id"] for item in value["finding_summaries"]
            ],
        }
    )
    return f"{REVIEW_ITEM_ID_PREFIX}{digest[:32]}"


def compute_review_item_hash(value: Mapping[str, Any]) -> str:
    """Return a tamper-evident hash for immutable review-item material."""

    payload = dict(value)
    payload.pop("item_hash_sha256", None)
    payload.pop("status", None)
    payload.pop("receipt_id", None)
    return _sha256_json(payload)


def compute_override_receipt_id(value: Mapping[str, Any]) -> str:
    """Return the deterministic id for an override receipt."""

    payload = dict(value)
    payload.pop("receipt_id", None)
    digest = _sha256_json(payload)
    return f"{OVERRIDE_RECEIPT_ID_PREFIX}{digest[:32]}"


@dataclass(frozen=True, slots=True)
class ReviewFindingSummary:
    """Secret-safe summary of a detector finding for local review."""

    finding_id: str
    risk_category: RiskCategory
    severity: RiskSeverity
    recommended_disposition: RecommendedDisposition
    detector_name: str
    explanation: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_string(self.finding_id, "finding_id", allow_empty=False, max_chars=96)
        if not isinstance(self.risk_category, RiskCategory):
            raise TypeError("risk_category must be a RiskCategory")
        if not isinstance(self.severity, RiskSeverity):
            raise TypeError("severity must be a RiskSeverity")
        if not isinstance(self.recommended_disposition, RecommendedDisposition):
            raise TypeError(
                "recommended_disposition must be a RecommendedDisposition"
            )
        object.__setattr__(
            self,
            "detector_name",
            _clean_reason_text(
                self.detector_name,
                "detector_name",
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "explanation",
            _clean_reason_text(
                self.explanation,
                "explanation",
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
        )
        limitations = _string_tuple(self.limitations, "limitations")
        object.__setattr__(
            self,
            "limitations",
            tuple(
                _clean_reason_text(
                    item,
                    "limitations",
                    max_chars=MAX_TEXT_FIELD_CHARS,
                )
                for item in limitations
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable finding summary."""

        return {
            "finding_id": self.finding_id,
            "risk_category": self.risk_category.value,
            "severity": self.severity.value,
            "recommended_disposition": self.recommended_disposition.value,
            "detector_name": self.detector_name,
            "explanation": self.explanation,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_scan_finding(cls, value: Any) -> "ReviewFindingSummary":
        """Build a review summary from a detector finding object."""

        return cls(
            finding_id=value.finding_id,
            risk_category=value.risk_category,
            severity=value.severity,
            recommended_disposition=value.recommended_disposition,
            detector_name=value.detector_name,
            explanation=value.explanation,
            limitations=value.limitations,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReviewFindingSummary":
        """Build a review finding summary from JSON-like data."""

        _reject_unknown_fields(value, _REVIEW_FINDING_SUMMARY_KEYS, "ReviewFindingSummary")
        return cls(
            finding_id=_require_string(
                value["finding_id"],
                "finding_id",
                allow_empty=False,
                max_chars=96,
            ),
            risk_category=_coerce_enum(
                RiskCategory,
                value["risk_category"],
                "risk_category",
            ),
            severity=_coerce_enum(RiskSeverity, value["severity"], "severity"),
            recommended_disposition=_coerce_enum(
                RecommendedDisposition,
                value["recommended_disposition"],
                "recommended_disposition",
            ),
            detector_name=_require_string(
                value["detector_name"],
                "detector_name",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            explanation=_require_string(
                value["explanation"],
                "explanation",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            limitations=_string_tuple(value["limitations"], "limitations"),
        )


@dataclass(frozen=True, slots=True)
class ReviewItem:
    """One high-risk scan event awaiting explicit local review."""

    item_id: str
    item_hash_sha256: str
    review_version: str
    source: str
    line_number: int
    event_id: str
    level: ScanEventLevel
    highest_disposition: RecommendedDisposition
    finding_count: int
    contradiction_count: int
    analysis_id: str
    trusted_state_action: TrustedStateAction
    assertion: MemoryStateAssertion
    reason_codes: tuple[str, ...]
    finding_summaries: tuple[ReviewFindingSummary, ...]
    status: ReviewItemStatus = ReviewItemStatus.PENDING
    receipt_id: str | None = None
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        if self.review_version != REVIEW_VERSION:
            raise ValueError(f"review_version must be {REVIEW_VERSION}")
        _require_string(
            self.item_id,
            "item_id",
            allow_empty=False,
            max_chars=96,
        )
        if not self.item_id.startswith(REVIEW_ITEM_ID_PREFIX):
            raise ValueError(f"item_id must start with {REVIEW_ITEM_ID_PREFIX}")
        _require_sha256(self.item_hash_sha256, "item_hash_sha256")
        _require_string(self.source, "source", allow_empty=False, max_chars=MAX_TEXT_FIELD_CHARS)
        if self.line_number < 1:
            raise ValueError("line_number must be positive")
        _require_string(self.event_id, "event_id", allow_empty=False, max_chars=96)
        if not isinstance(self.level, ScanEventLevel):
            raise TypeError("level must be a ScanEventLevel")
        if self.level != ScanEventLevel.HIGH_RISK:
            raise ValueError("only high-risk scan events can become review items")
        if not isinstance(self.highest_disposition, RecommendedDisposition):
            raise TypeError("highest_disposition must be a RecommendedDisposition")
        if self.finding_count < 0:
            raise ValueError("finding_count must be non-negative")
        if self.contradiction_count < 0:
            raise ValueError("contradiction_count must be non-negative")
        _require_string(
            self.analysis_id,
            "analysis_id",
            allow_empty=False,
            max_chars=96,
        )
        object.__setattr__(
            self,
            "trusted_state_action",
            _coerce_enum(
                TrustedStateAction,
                self.trusted_state_action,
                "trusted_state_action",
            ),
        )
        if not isinstance(self.assertion, MemoryStateAssertion):
            raise TypeError("assertion must be a MemoryStateAssertion")
        if self.assertion.source_event_id != self.event_id:
            raise ValueError("assertion source_event_id must match event_id")
        object.__setattr__(
            self,
            "reason_codes",
            _string_tuple(self.reason_codes, "reason_codes"),
        )
        if any(not isinstance(item, ReviewFindingSummary) for item in self.finding_summaries):
            raise TypeError("finding_summaries must contain ReviewFindingSummary objects")
        if self.finding_count != len(self.finding_summaries):
            raise ValueError("finding_count must match finding_summaries")
        object.__setattr__(
            self,
            "status",
            _coerce_enum(ReviewItemStatus, self.status, "status"),
        )
        if self.receipt_id is not None:
            _require_string(
                self.receipt_id,
                "receipt_id",
                allow_empty=False,
                max_chars=96,
            )
            if not self.receipt_id.startswith(OVERRIDE_RECEIPT_ID_PREFIX):
                raise ValueError(
                    f"receipt_id must start with {OVERRIDE_RECEIPT_ID_PREFIX}"
                )
        if self.status == ReviewItemStatus.PENDING and self.receipt_id is not None:
            raise ValueError("pending review items must not have receipt_id")
        if self.status != ReviewItemStatus.PENDING and self.receipt_id is None:
            raise ValueError("decided review items must have receipt_id")
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))
        expected_id = compute_review_item_id(self._identity_payload())
        if self.item_id != expected_id:
            raise ValueError(f"item_id mismatch: expected {expected_id}")
        expected_hash = compute_review_item_hash(self._immutable_payload())
        if self.item_hash_sha256 != expected_hash:
            raise ValueError(f"item_hash_sha256 mismatch: expected {expected_hash}")

    @property
    def finding_ids(self) -> tuple[str, ...]:
        """Return finding ids attached to this review item."""

        return tuple(item.finding_id for item in self.finding_summaries)

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line_number": self.line_number,
            "event_id": self.event_id,
            "analysis_id": self.analysis_id,
            "assertion": self.assertion.to_dict(),
            "trusted_state_action": self.trusted_state_action.value,
            "finding_summaries": [item.to_dict() for item in self.finding_summaries],
        }

    def _immutable_payload(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "review_version": self.review_version,
            "source": self.source,
            "line_number": self.line_number,
            "event_id": self.event_id,
            "level": self.level.value,
            "highest_disposition": self.highest_disposition.value,
            "finding_count": self.finding_count,
            "contradiction_count": self.contradiction_count,
            "analysis_id": self.analysis_id,
            "trusted_state_action": self.trusted_state_action.value,
            "assertion": self.assertion.to_dict(),
            "reason_codes": list(self.reason_codes),
            "finding_summaries": [item.to_dict() for item in self.finding_summaries],
            "metadata": _metadata_dict(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable review item."""

        return {
            **self._immutable_payload(),
            "item_hash_sha256": self.item_hash_sha256,
            "status": self.status.value,
            "receipt_id": self.receipt_id,
        }

    @classmethod
    def from_scan_event(cls, source: str, value: ScanEventResult) -> "ReviewItem":
        """Build a pending review item from one high-risk scan result."""

        finding_summaries = tuple(
            ReviewFindingSummary.from_scan_finding(item)
            for item in value.detector_result.findings
        )
        identity_payload = {
            "source": source,
            "line_number": value.line_number,
            "event_id": value.event_id,
            "analysis_id": value.state_analysis.analysis_id,
            "assertion": value.state_analysis.assertion.to_dict(),
            "trusted_state_action": value.state_analysis.trusted_state_action.value,
            "finding_summaries": [item.to_dict() for item in finding_summaries],
        }
        item_id = compute_review_item_id(identity_payload)
        review_metadata: dict[str, JSONScalar] = {
            "input_contract": "ScanEventResult",
            "source_scan_version": SCAN_VERSION,
        }
        immutable_payload: dict[str, Any] = {
            "item_id": item_id,
            "review_version": REVIEW_VERSION,
            "source": source,
            "line_number": value.line_number,
            "event_id": value.event_id,
            "level": value.level.value,
            "highest_disposition": value.highest_disposition.value,
            "finding_count": value.finding_count,
            "contradiction_count": value.contradiction_count,
            "analysis_id": value.state_analysis.analysis_id,
            "trusted_state_action": value.state_analysis.trusted_state_action.value,
            "assertion": value.state_analysis.assertion.to_dict(),
            "reason_codes": list(value.state_analysis.reason_codes),
            "finding_summaries": [item.to_dict() for item in finding_summaries],
            "metadata": review_metadata,
        }
        return cls(
            item_id=item_id,
            item_hash_sha256=compute_review_item_hash(immutable_payload),
            review_version=REVIEW_VERSION,
            source=source,
            line_number=value.line_number,
            event_id=value.event_id,
            level=value.level,
            highest_disposition=value.highest_disposition,
            finding_count=value.finding_count,
            contradiction_count=value.contradiction_count,
            analysis_id=value.state_analysis.analysis_id,
            trusted_state_action=value.state_analysis.trusted_state_action,
            assertion=value.state_analysis.assertion,
            reason_codes=value.state_analysis.reason_codes,
            finding_summaries=finding_summaries,
            metadata=review_metadata,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReviewItem":
        """Build a review item from JSON-like data."""

        _reject_unknown_fields(value, _REVIEW_ITEM_KEYS, "ReviewItem")
        summaries_payload = value["finding_summaries"]
        if isinstance(summaries_payload, str) or not isinstance(
            summaries_payload,
            (list, tuple),
        ):
            raise TypeError("finding_summaries must be an array")
        receipt_id = value.get("receipt_id")
        if receipt_id is not None and not isinstance(receipt_id, str):
            raise TypeError("receipt_id must be a string or null")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        return cls(
            item_id=_require_string(
                value["item_id"],
                "item_id",
                allow_empty=False,
                max_chars=96,
            ),
            item_hash_sha256=_require_sha256(
                value["item_hash_sha256"],
                "item_hash_sha256",
            ),
            review_version=_require_string(
                value["review_version"],
                "review_version",
                allow_empty=False,
                max_chars=64,
            ),
            source=_require_string(
                value["source"],
                "source",
                allow_empty=False,
                max_chars=MAX_TEXT_FIELD_CHARS,
            ),
            line_number=_require_int(value["line_number"], "line_number"),
            event_id=_require_string(
                value["event_id"],
                "event_id",
                allow_empty=False,
                max_chars=96,
            ),
            level=_coerce_enum(ScanEventLevel, value["level"], "level"),
            highest_disposition=_coerce_enum(
                RecommendedDisposition,
                value["highest_disposition"],
                "highest_disposition",
            ),
            finding_count=_require_int(value["finding_count"], "finding_count"),
            contradiction_count=_require_int(
                value["contradiction_count"],
                "contradiction_count",
            ),
            analysis_id=_require_string(
                value["analysis_id"],
                "analysis_id",
                allow_empty=False,
                max_chars=96,
            ),
            trusted_state_action=_coerce_enum(
                TrustedStateAction,
                value["trusted_state_action"],
                "trusted_state_action",
            ),
            assertion=MemoryStateAssertion.from_dict(value["assertion"]),
            reason_codes=_string_tuple(value["reason_codes"], "reason_codes"),
            finding_summaries=tuple(
                ReviewFindingSummary.from_dict(item) for item in summaries_payload
            ),
            status=_coerce_enum(ReviewItemStatus, value["status"], "status"),
            receipt_id=receipt_id,
            metadata=_coerce_metadata(metadata),
        )


@dataclass(frozen=True, slots=True)
class OverrideReceipt:
    """Deterministic local receipt for an allow/reject decision."""

    receipt_id: str
    receipt_version: str
    item_id: str
    item_hash_sha256: str
    decision: OverrideDecision
    reason: str
    reviewer: str
    event_id: str
    assertion_id: str
    finding_ids: tuple[str, ...]
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        if self.receipt_version != REVIEW_VERSION:
            raise ValueError(f"receipt_version must be {REVIEW_VERSION}")
        _require_string(
            self.receipt_id,
            "receipt_id",
            allow_empty=False,
            max_chars=96,
        )
        if not self.receipt_id.startswith(OVERRIDE_RECEIPT_ID_PREFIX):
            raise ValueError(
                f"receipt_id must start with {OVERRIDE_RECEIPT_ID_PREFIX}"
            )
        _require_string(self.item_id, "item_id", allow_empty=False, max_chars=96)
        if not self.item_id.startswith(REVIEW_ITEM_ID_PREFIX):
            raise ValueError(f"item_id must start with {REVIEW_ITEM_ID_PREFIX}")
        _require_sha256(self.item_hash_sha256, "item_hash_sha256")
        object.__setattr__(
            self,
            "decision",
            _coerce_enum(OverrideDecision, self.decision, "decision"),
        )
        object.__setattr__(
            self,
            "reason",
            _clean_reason_text(self.reason, "reason", max_chars=MAX_REASON_CHARS),
        )
        object.__setattr__(
            self,
            "reviewer",
            _clean_reason_text(
                self.reviewer,
                "reviewer",
                max_chars=MAX_REVIEWER_CHARS,
            ),
        )
        _require_string(self.event_id, "event_id", allow_empty=False, max_chars=96)
        _require_string(
            self.assertion_id,
            "assertion_id",
            allow_empty=False,
            max_chars=96,
        )
        object.__setattr__(
            self,
            "finding_ids",
            _string_tuple(self.finding_ids, "finding_ids"),
        )
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))
        expected = compute_override_receipt_id(self.to_dict())
        if self.receipt_id != expected:
            raise ValueError(f"receipt_id mismatch: expected {expected}")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable override receipt."""

        return {
            "receipt_id": self.receipt_id,
            "receipt_version": self.receipt_version,
            "item_id": self.item_id,
            "item_hash_sha256": self.item_hash_sha256,
            "decision": self.decision.value,
            "reason": self.reason,
            "reviewer": self.reviewer,
            "event_id": self.event_id,
            "assertion_id": self.assertion_id,
            "finding_ids": list(self.finding_ids),
            "metadata": _metadata_dict(self.metadata),
        }

    @classmethod
    def from_item(
        cls,
        item: ReviewItem,
        *,
        decision: OverrideDecision,
        reason: str,
        reviewer: str = DEFAULT_REVIEWER,
    ) -> "OverrideReceipt":
        """Build a deterministic receipt for one item decision."""

        safe_reason = _clean_reason_text(reason, "reason", max_chars=MAX_REASON_CHARS)
        safe_reviewer = _clean_reason_text(
            reviewer,
            "reviewer",
            max_chars=MAX_REVIEWER_CHARS,
        )
        receipt_metadata: dict[str, JSONScalar] = {
            "receipt_contract": "local_override_only",
            "trusted_ledger_write": False,
        }
        payload: dict[str, Any] = {
            "receipt_version": REVIEW_VERSION,
            "item_id": item.item_id,
            "item_hash_sha256": item.item_hash_sha256,
            "decision": decision.value,
            "reason": safe_reason,
            "reviewer": safe_reviewer,
            "event_id": item.event_id,
            "assertion_id": item.assertion.assertion_id,
            "finding_ids": list(item.finding_ids),
            "metadata": receipt_metadata,
        }
        return cls(
            receipt_id=compute_override_receipt_id(payload),
            receipt_version=REVIEW_VERSION,
            item_id=item.item_id,
            item_hash_sha256=item.item_hash_sha256,
            decision=decision,
            reason=safe_reason,
            reviewer=safe_reviewer,
            event_id=item.event_id,
            assertion_id=item.assertion.assertion_id,
            finding_ids=item.finding_ids,
            metadata=receipt_metadata,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OverrideReceipt":
        """Build an override receipt from JSON-like data."""

        _reject_unknown_fields(value, _OVERRIDE_RECEIPT_KEYS, "OverrideReceipt")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        return cls(
            receipt_id=_require_string(
                value["receipt_id"],
                "receipt_id",
                allow_empty=False,
                max_chars=96,
            ),
            receipt_version=_require_string(
                value["receipt_version"],
                "receipt_version",
                allow_empty=False,
                max_chars=64,
            ),
            item_id=_require_string(
                value["item_id"],
                "item_id",
                allow_empty=False,
                max_chars=96,
            ),
            item_hash_sha256=_require_sha256(
                value["item_hash_sha256"],
                "item_hash_sha256",
            ),
            decision=_coerce_enum(OverrideDecision, value["decision"], "decision"),
            reason=_require_string(
                value["reason"],
                "reason",
                allow_empty=False,
                max_chars=MAX_REASON_CHARS,
            ),
            reviewer=_require_string(
                value["reviewer"],
                "reviewer",
                allow_empty=False,
                max_chars=MAX_REVIEWER_CHARS,
            ),
            event_id=_require_string(
                value["event_id"],
                "event_id",
                allow_empty=False,
                max_chars=96,
            ),
            assertion_id=_require_string(
                value["assertion_id"],
                "assertion_id",
                allow_empty=False,
                max_chars=96,
            ),
            finding_ids=_string_tuple(value["finding_ids"], "finding_ids"),
            metadata=_coerce_metadata(metadata),
        )


@dataclass(frozen=True, slots=True)
class ReviewQueue:
    """File-serializable local review queue."""

    review_version: str = REVIEW_VERSION
    items: tuple[ReviewItem, ...] = ()
    receipts: tuple[OverrideReceipt, ...] = ()
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        if self.review_version != REVIEW_VERSION:
            raise ValueError(f"review_version must be {REVIEW_VERSION}")
        if any(not isinstance(item, ReviewItem) for item in self.items):
            raise TypeError("items must contain ReviewItem objects")
        if any(not isinstance(item, OverrideReceipt) for item in self.receipts):
            raise TypeError("receipts must contain OverrideReceipt objects")
        item_ids = [item.item_id for item in self.items]
        if len(set(item_ids)) != len(item_ids):
            raise ValueError("review queue item ids must be unique")
        receipt_ids = [receipt.receipt_id for receipt in self.receipts]
        if len(set(receipt_ids)) != len(receipt_ids):
            raise ValueError("review queue receipt ids must be unique")
        receipts_by_id = {receipt.receipt_id: receipt for receipt in self.receipts}
        for item in self.items:
            if item.status == ReviewItemStatus.PENDING:
                continue
            if item.receipt_id is None or item.receipt_id not in receipts_by_id:
                raise ValueError("decided review item must reference a queue receipt")
            receipt = receipts_by_id[item.receipt_id]
            if receipt.item_id != item.item_id:
                raise ValueError("receipt item_id must match review item")
            if receipt.item_hash_sha256 != item.item_hash_sha256:
                raise ValueError("receipt item_hash_sha256 must match review item")
            if item.status == ReviewItemStatus.ALLOWED and receipt.decision != OverrideDecision.ALLOW:
                raise ValueError("allowed item must reference an allow receipt")
            if item.status == ReviewItemStatus.REJECTED and receipt.decision != OverrideDecision.REJECT:
                raise ValueError("rejected item must reference a reject receipt")
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))

    @classmethod
    def empty(cls) -> "ReviewQueue":
        """Return an empty local review queue."""

        return cls(metadata={"queue_contract": "local_file_only"})

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable review queue."""

        return {
            "review_version": self.review_version,
            "items": [item.to_dict() for item in self.items],
            "receipts": [receipt.to_dict() for receipt in self.receipts],
            "metadata": _metadata_dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReviewQueue":
        """Build a review queue from JSON-like data."""

        _reject_unknown_fields(value, _REVIEW_QUEUE_KEYS, "ReviewQueue")
        items_payload = value["items"]
        receipts_payload = value["receipts"]
        metadata = value.get("metadata", {})
        if isinstance(items_payload, str) or not isinstance(items_payload, (list, tuple)):
            raise TypeError("items must be an array")
        if isinstance(receipts_payload, str) or not isinstance(
            receipts_payload,
            (list, tuple),
        ):
            raise TypeError("receipts must be an array")
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        return cls(
            review_version=_require_string(
                value["review_version"],
                "review_version",
                allow_empty=False,
                max_chars=64,
            ),
            items=tuple(ReviewItem.from_dict(item) for item in items_payload),
            receipts=tuple(
                OverrideReceipt.from_dict(item) for item in receipts_payload
            ),
            metadata=_coerce_metadata(metadata),
        )


def enqueue_scan_result(
    scan_result: ScanResult,
    queue: ReviewQueue | None = None,
) -> ReviewQueue:
    """Return a queue with high-risk scan events added as pending review items."""

    active_queue = queue or ReviewQueue.empty()
    existing_item_ids = {item.item_id for item in active_queue.items}
    items = list(active_queue.items)
    for event in scan_result.events:
        if event.level != ScanEventLevel.HIGH_RISK:
            continue
        item = ReviewItem.from_scan_event(scan_result.source, event)
        if item.item_id in existing_item_ids:
            continue
        existing_item_ids.add(item.item_id)
        items.append(item)
    metadata = _metadata_dict(active_queue.metadata)
    metadata.update(
        {
            "last_enqueue_source": scan_result.source,
            "last_enqueue_scan_version": scan_result.scan_version,
        }
    )
    return ReviewQueue(
        review_version=REVIEW_VERSION,
        items=tuple(items),
        receipts=active_queue.receipts,
        metadata=metadata,
    )


def _decide_review_item(
    queue: ReviewQueue,
    *,
    item_id: str,
    decision: OverrideDecision,
    reason: str,
    reviewer: str,
) -> ReviewQueue:
    items = list(queue.items)
    for index, item in enumerate(items):
        if item.item_id != item_id:
            continue
        receipt = OverrideReceipt.from_item(
            item,
            decision=decision,
            reason=reason,
            reviewer=reviewer,
        )
        if item.status != ReviewItemStatus.PENDING:
            existing_receipt = next(
                (
                    existing
                    for existing in queue.receipts
                    if existing.receipt_id == item.receipt_id
                ),
                None,
            )
            if existing_receipt is not None and existing_receipt.to_dict() == receipt.to_dict():
                return queue
            raise ValueError("review item is already decided")
        status = (
            ReviewItemStatus.ALLOWED
            if decision == OverrideDecision.ALLOW
            else ReviewItemStatus.REJECTED
        )
        items[index] = replace(item, status=status, receipt_id=receipt.receipt_id)
        return ReviewQueue(
            review_version=REVIEW_VERSION,
            items=tuple(items),
            receipts=queue.receipts + (receipt,),
            metadata=queue.metadata,
        )
    raise ValueError(f"review item not found: {item_id}")


def allow_review_item(
    queue: ReviewQueue,
    item_id: str,
    *,
    reason: str,
    reviewer: str = DEFAULT_REVIEWER,
) -> ReviewQueue:
    """Mark a pending item allowed and attach a deterministic receipt."""

    return _decide_review_item(
        queue,
        item_id=item_id,
        decision=OverrideDecision.ALLOW,
        reason=reason,
        reviewer=reviewer,
    )


def reject_review_item(
    queue: ReviewQueue,
    item_id: str,
    *,
    reason: str,
    reviewer: str = DEFAULT_REVIEWER,
) -> ReviewQueue:
    """Mark a pending item rejected and attach a deterministic receipt."""

    return _decide_review_item(
        queue,
        item_id=item_id,
        decision=OverrideDecision.REJECT,
        reason=reason,
        reviewer=reviewer,
    )


@dataclass(frozen=True, slots=True)
class TrustedReadPreviewItem:
    """One receipted assertion visible to the local trusted-read preview."""

    item_id: str
    event_id: str
    assertion: MemoryStateAssertion
    receipt: OverrideReceipt
    preview_status: str = TRUSTED_READ_PREVIEW_STATUS

    def __post_init__(self) -> None:
        _require_string(self.item_id, "item_id", allow_empty=False, max_chars=96)
        _require_string(self.event_id, "event_id", allow_empty=False, max_chars=96)
        if not isinstance(self.assertion, MemoryStateAssertion):
            raise TypeError("assertion must be a MemoryStateAssertion")
        if not isinstance(self.receipt, OverrideReceipt):
            raise TypeError("receipt must be an OverrideReceipt")
        if self.assertion.source_event_id != self.event_id:
            raise ValueError("assertion source_event_id must match event_id")
        if self.receipt.item_id != self.item_id:
            raise ValueError("receipt item_id must match item_id")
        if self.receipt.decision != OverrideDecision.ALLOW:
            raise ValueError("trusted-read preview items require allow receipts")
        if self.preview_status != TRUSTED_READ_PREVIEW_STATUS:
            raise ValueError(
                f"preview_status must be {TRUSTED_READ_PREVIEW_STATUS}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable trusted-read preview item."""

        return {
            "item_id": self.item_id,
            "event_id": self.event_id,
            "assertion": self.assertion.to_dict(),
            "receipt": self.receipt.to_dict(),
            "preview_status": self.preview_status,
        }


@dataclass(frozen=True, slots=True)
class TrustedReadPreview:
    """Local preview of allowed review items, not a trusted ledger write."""

    preview_version: str
    items: tuple[TrustedReadPreviewItem, ...]
    limitations: tuple[str, ...]
    metadata: Mapping[str, JSONScalar] | None = None

    def __post_init__(self) -> None:
        if self.preview_version != REVIEW_VERSION:
            raise ValueError(f"preview_version must be {REVIEW_VERSION}")
        if any(not isinstance(item, TrustedReadPreviewItem) for item in self.items):
            raise TypeError("items must contain TrustedReadPreviewItem objects")
        object.__setattr__(
            self,
            "limitations",
            _string_tuple(self.limitations, "limitations"),
        )
        metadata = {} if self.metadata is None else self.metadata
        object.__setattr__(self, "metadata", _freeze_metadata(metadata))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable trusted-read preview."""

        return {
            "preview_version": self.preview_version,
            "items": [item.to_dict() for item in self.items],
            "limitations": list(self.limitations),
            "metadata": _metadata_dict(self.metadata),
        }


def trusted_read_preview(queue: ReviewQueue) -> TrustedReadPreview:
    """Return allowed queue items as a local receipted read preview."""

    receipts_by_id = {receipt.receipt_id: receipt for receipt in queue.receipts}
    preview_items: list[TrustedReadPreviewItem] = []
    for item in queue.items:
        if item.status != ReviewItemStatus.ALLOWED:
            continue
        if item.receipt_id is None:
            raise ValueError("allowed item is missing receipt_id")
        receipt = receipts_by_id[item.receipt_id]
        preview_items.append(
            TrustedReadPreviewItem(
                item_id=item.item_id,
                event_id=item.event_id,
                assertion=item.assertion,
                receipt=receipt,
            )
        )
    return TrustedReadPreview(
        preview_version=REVIEW_VERSION,
        items=tuple(preview_items),
        limitations=(
            "Local preview only.",
            "Does not write trusted ledger state.",
            "Does not prove objective truth.",
            "Rejected and pending items are excluded from preview items.",
        ),
        metadata={
            "allowed_count": len(preview_items),
            "pending_count": sum(
                1 for item in queue.items if item.status == ReviewItemStatus.PENDING
            ),
            "rejected_count": sum(
                1 for item in queue.items if item.status == ReviewItemStatus.REJECTED
            ),
            "trusted_ledger_write": False,
        },
    )


def load_review_queue(path: str | Path) -> ReviewQueue:
    """Load a review queue JSON file."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise TypeError("review queue JSON must be an object")
    return ReviewQueue.from_dict(payload)


def save_review_queue(path: str | Path, queue: ReviewQueue) -> None:
    """Write a review queue JSON file atomically enough for local CLI use."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.tmp")
    tmp.write_text(
        json.dumps(queue.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(target)
