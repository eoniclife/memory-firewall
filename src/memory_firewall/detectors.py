"""Deterministic local detectors for supplied MemoryEvent payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Callable

from .models import (
    EvidenceField,
    EvidenceSpan,
    MemoryEvent,
    MemoryFinding,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    SourceType,
)
from .policy import PolicyRecommendation, recommend_policy

DETECTOR_PACK_NAME = "memory-firewall-default-detectors"
DETECTOR_PACK_VERSION = "mf-04"
DETECTOR_VERSION = "mf-04"

DetectorFn = Callable[["DetectorDefinition", MemoryEvent], MemoryFinding | None]


@dataclass(frozen=True, slots=True)
class DetectorDefinition:
    """Machine-readable metadata for one deterministic detector."""

    name: str
    version: str
    risk_category: RiskCategory
    description: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name must not be empty")
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("version must not be empty")
        if self.version != DETECTOR_VERSION:
            raise ValueError(f"version must be {DETECTOR_VERSION}")
        if not isinstance(self.risk_category, RiskCategory):
            raise TypeError("risk_category must be a RiskCategory")
        if not isinstance(self.description, str) or not self.description:
            raise ValueError("description must not be empty")
        if isinstance(self.limitations, str) or not isinstance(self.limitations, tuple):
            raise TypeError("limitations must be a tuple of strings")
        if not self.limitations:
            raise ValueError("limitations must not be empty")
        if any(not isinstance(item, str) or not item for item in self.limitations):
            raise ValueError("limitations must contain non-empty strings")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable detector definition."""

        return {
            "name": self.name,
            "version": self.version,
            "risk_category": self.risk_category.value,
            "description": self.description,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class DetectorPack:
    """Ordered deterministic detector pack."""

    name: str
    version: str
    definitions: tuple[DetectorDefinition, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name must not be empty")
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("version must not be empty")
        if self.version != DETECTOR_PACK_VERSION:
            raise ValueError(f"version must be {DETECTOR_PACK_VERSION}")
        if isinstance(self.definitions, str) or not isinstance(self.definitions, tuple):
            raise TypeError("definitions must be a tuple of DetectorDefinition objects")
        if not self.definitions:
            raise ValueError("definitions must not be empty")
        seen: set[str] = set()
        for definition in self.definitions:
            if not isinstance(definition, DetectorDefinition):
                raise TypeError("definitions must contain DetectorDefinition objects")
            if definition.name in seen:
                raise ValueError(f"duplicate detector definition: {definition.name}")
            if definition.name not in _DETECTOR_FUNCTIONS:
                raise ValueError(f"no detector implementation for {definition.name}")
            canonical = _DETECTOR_DEFINITION_BY_NAME[definition.name]
            if definition != canonical:
                raise ValueError(
                    f"detector definition must match built-in metadata: "
                    f"{definition.name}"
                )
            seen.add(definition.name)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable detector pack description."""

        return {
            "name": self.name,
            "version": self.version,
            "definitions": [definition.to_dict() for definition in self.definitions],
        }

    def run(self, event: MemoryEvent) -> "DetectorResult":
        """Run every detector in pack order against one event."""

        if not event.has_expected_event_id():
            raise ValueError("event_id must match canonical event material")
        findings: list[MemoryFinding] = []
        for definition in self.definitions:
            finding = _DETECTOR_FUNCTIONS[definition.name](definition, event)
            if finding is not None:
                finding.validate_against_event(event)
                findings.append(finding)
        return DetectorResult(
            event_id=event.event_id,
            pack_name=self.name,
            pack_version=self.version,
            findings=tuple(findings),
            policy_recommendations=tuple(recommend_policy(item) for item in findings),
        )


@dataclass(frozen=True, slots=True)
class DetectorResult:
    """Findings produced by running one detector pack over one event."""

    event_id: str
    pack_name: str
    pack_version: str
    findings: tuple[MemoryFinding, ...]
    policy_recommendations: tuple[PolicyRecommendation, ...]

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id must not be empty")
        if not self.pack_name:
            raise ValueError("pack_name must not be empty")
        if not self.pack_version:
            raise ValueError("pack_version must not be empty")
        if len(self.findings) != len(self.policy_recommendations):
            raise ValueError("policy_recommendations must match findings")
        finding_ids = {finding.finding_id for finding in self.findings}
        recommendation_ids = {
            recommendation.finding_id for recommendation in self.policy_recommendations
        }
        if any(finding.event_id != self.event_id for finding in self.findings):
            raise ValueError("all findings must match event_id")
        if finding_ids != recommendation_ids:
            raise ValueError("policy_recommendations must match finding ids")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable detector result."""

        return {
            "event_id": self.event_id,
            "pack_name": self.pack_name,
            "pack_version": self.pack_version,
            "findings": [finding.to_dict() for finding in self.findings],
            "policy_recommendations": [
                recommendation.to_dict()
                for recommendation in self.policy_recommendations
            ],
        }


def default_detector_pack() -> DetectorPack:
    """Return the built-in deterministic detector pack."""

    return DetectorPack(
        name=DETECTOR_PACK_NAME,
        version=DETECTOR_PACK_VERSION,
        definitions=_DETECTOR_DEFINITIONS,
    )


def run_detectors(
    event: MemoryEvent, pack: DetectorPack | None = None
) -> DetectorResult:
    """Run deterministic detectors over one supplied event."""

    active_pack = pack or default_detector_pack()
    return active_pack.run(event)


def _make_finding(
    definition: DetectorDefinition,
    event: MemoryEvent,
    span: EvidenceSpan,
    *,
    severity: RiskSeverity,
    confidence: float,
    explanation: str,
    recommended_disposition: RecommendedDisposition,
    limitations: tuple[str, ...] = (),
) -> MemoryFinding:
    return MemoryFinding.from_detector_payload(
        {
            "event_id": event.event_id,
            "risk_category": definition.risk_category.value,
            "severity": severity.value,
            "confidence": confidence,
            "evidence_span": span.to_dict(),
            "detector_name": definition.name,
            "detector_version": definition.version,
            "explanation": explanation,
            "recommended_disposition": recommended_disposition.value,
            "limitations": list(definition.limitations + limitations),
        }
    )


def _event_text(event: MemoryEvent, field: EvidenceField) -> str:
    if field == EvidenceField.PROPOSED_MEMORY:
        return event.proposed_memory
    if field == EvidenceField.RAW_OR_REDACTED_CONTENT:
        return event.raw_or_redacted_content
    if field == EvidenceField.TIMESTAMP:
        return event.timestamp
    if field == EvidenceField.SOURCE_TYPE:
        return event.source_type.value
    if field == EvidenceField.SOURCE_ID:
        return event.source_id
    if field == EvidenceField.SOURCE_AUTHORITY:
        return event.source_authority.value
    raise ValueError(f"unsupported event text field: {field}")


def _first_nonempty_span(event: MemoryEvent) -> EvidenceSpan | None:
    for field in (
        EvidenceField.PROPOSED_MEMORY,
        EvidenceField.RAW_OR_REDACTED_CONTENT,
    ):
        text = _event_text(event, field)
        if text:
            end = min(len(text), 160)
            return EvidenceSpan(field, 0, end, text[:end])
    return None


def _regex_span(event: MemoryEvent, patterns: tuple[re.Pattern[str], ...]) -> EvidenceSpan | None:
    for field in (
        EvidenceField.PROPOSED_MEMORY,
        EvidenceField.RAW_OR_REDACTED_CONTENT,
    ):
        text = _event_text(event, field)
        for pattern in patterns:
            match = pattern.search(text)
            if match is not None and match.end() > match.start():
                return EvidenceSpan(
                    source_field=field,
                    start=match.start(),
                    end=match.end(),
                    quote=text[match.start() : match.end()],
                )
    return None


def _detect_provenance_gap(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    low_authority = event.source_authority in {
        SourceAuthority.UNKNOWN,
        SourceAuthority.UNTRUSTED,
    }
    unknown_source = event.source_type == SourceType.UNKNOWN
    vague_source_id = event.source_id.strip().lower() in {"unknown", "n/a", "none"}
    if not (low_authority or unknown_source or vague_source_id):
        return None
    if low_authority:
        source_field = EvidenceField.SOURCE_AUTHORITY
    elif unknown_source:
        source_field = EvidenceField.SOURCE_TYPE
    else:
        source_field = EvidenceField.SOURCE_ID
    quote = _event_text(event, source_field)
    span = EvidenceSpan(source_field, 0, len(quote), quote)
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.SUSPICIOUS,
        confidence=0.72,
        explanation=(
            "The memory is backed by unknown or untrusted source authority, so "
            "it should be reviewed before being treated as durable trusted state."
        ),
        recommended_disposition=RecommendedDisposition.REVIEW,
    )


_INSTRUCTION_PATTERNS = (
    re.compile(r"\b(ignore|disregard)\b.{0,48}\b(previous|prior|system|developer|instruction)s?\b", re.I | re.S),
    re.compile(r"\b(system|developer)\s+prompt\b", re.I),
    re.compile(r"\b(always|forever)\s+(obey|follow|trust|remember)\b", re.I),
    re.compile(r"\bdo\s+not\s+(tell|reveal|mention)\b", re.I),
)


def _detect_instruction_pattern(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    span = _regex_span(event, _INSTRUCTION_PATTERNS)
    if span is None:
        return None
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.HIGH_IMPACT,
        confidence=0.9,
        explanation=(
            "The event contains instruction-like language that could persist "
            "behavior changes into memory."
        ),
        recommended_disposition=RecommendedDisposition.QUARANTINE,
    )


_AUTHORITY_PATTERNS = (
    re.compile(r"\b(owner|admin|approver|approval|signer|controller)\b.{0,48}\b(is|are|to|goes?|changes?|becomes?)\b", re.I | re.S),
    re.compile(r"\b(payment|payout|wire|bank\s+account|invoice)\b.{0,64}\b(change|route|send|approve|recipient|beneficiary)\b", re.I | re.S),
    re.compile(r"\b(approve|authorize)\b.{0,48}\b(payment|payout|wire|transfer|access)\b", re.I | re.S),
)


def _detect_authority_change(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    span = _regex_span(event, _AUTHORITY_PATTERNS)
    if span is None:
        return None
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.HIGH_IMPACT,
        confidence=0.78,
        explanation=(
            "The memory appears to change authority, ownership, payment, or "
            "approval state."
        ),
        recommended_disposition=RecommendedDisposition.REVIEW,
    )


_DATE_PATTERN = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
_TEMPORAL_LANGUAGE = (
    re.compile(r"\b(current|latest|now|still|always)\b.{0,40}\b(status|owner|policy|price|rate|address)\b", re.I | re.S),
    re.compile(r"\b(as\s+of|last\s+updated|effective)\b", re.I),
)


def _event_day(event: MemoryEvent) -> date | None:
    try:
        normalized = (
            event.timestamp[:-1] + "+00:00"
            if event.timestamp.endswith("Z")
            else event.timestamp
        )
        return datetime.fromisoformat(normalized).date()
    except ValueError:
        return None


def _detect_stale_temporal_state(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    event_day = _event_day(event)
    for field in (
        EvidenceField.PROPOSED_MEMORY,
        EvidenceField.RAW_OR_REDACTED_CONTENT,
    ):
        text = _event_text(event, field)
        for match in _DATE_PATTERN.finditer(text):
            if event_day is None:
                continue
            try:
                mentioned_day = date.fromisoformat(match.group(0))
            except ValueError:
                continue
            if (event_day - mentioned_day).days >= 365:
                date_span = EvidenceSpan(
                    field, match.start(), match.end(), match.group(0)
                )
                return _make_finding(
                    definition,
                    event,
                    date_span,
                    severity=RiskSeverity.SUSPICIOUS,
                    confidence=0.74,
                    explanation=(
                        "The memory contains date-bearing state that is at least "
                        "one year older than the event timestamp."
                    ),
                    recommended_disposition=RecommendedDisposition.REVIEW,
                    limitations=("Uses event timestamp comparison only.",),
                )
    span = _regex_span(event, _TEMPORAL_LANGUAGE)
    if span is None:
        return None
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.INFORMATIONAL,
        confidence=0.58,
        explanation=(
            "The memory uses temporal language that may become stale without a "
            "freshness source."
        ),
        recommended_disposition=RecommendedDisposition.WARN,
    )


_SCOPE_PRIVACY_PATTERNS = (
    re.compile(r"\b(cross[-\s]?tenant|another tenant|other tenant|different customer)\b", re.I),
    re.compile(r"\b(confidential|private|internal only|do not share|personal data|pii)\b", re.I),
    re.compile(r"\b(ssn|social security|passport|medical record|patient)\b", re.I),
)


def _detect_scope_privacy(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    span = _regex_span(event, _SCOPE_PRIVACY_PATTERNS)
    if span is None:
        return None
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.HIGH_IMPACT,
        confidence=0.82,
        explanation=(
            "The memory appears to mention privacy-sensitive or cross-scope "
            "content."
        ),
        recommended_disposition=RecommendedDisposition.REVIEW,
    )


_SECRET_LABEL_PATTERN = re.compile(
    r"\b(?P<label>api[_\-\s]?key|secret|password|passwd|token)\b"
    r"\s*[:=]\s*(?P<secret>[A-Za-z0-9_\-]{8,})",
    re.I,
)
_OPENAI_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")
_CARD_LIKE_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _secret_evidence_span(event: MemoryEvent) -> EvidenceSpan | None:
    for field in (
        EvidenceField.PROPOSED_MEMORY,
        EvidenceField.RAW_OR_REDACTED_CONTENT,
    ):
        text = _event_text(event, field)
        label_match = _SECRET_LABEL_PATTERN.search(text)
        if label_match is not None:
            start, end = label_match.span("label")
            return EvidenceSpan(field, start, end, text[start:end])
        key_match = _OPENAI_KEY_PATTERN.search(text)
        if key_match is not None:
            start = key_match.start()
            end = min(start + 3, key_match.end())
            return EvidenceSpan(field, start, end, text[start:end])
        card_match = _CARD_LIKE_PATTERN.search(text)
        if card_match is not None:
            start = card_match.start()
            end = min(start + 4, card_match.end())
            return EvidenceSpan(field, start, end, text[start:end])
    return None


def _detect_secret_pattern(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    span = _secret_evidence_span(event)
    if span is None:
        return None
    return _make_finding(
        definition,
        event,
        span,
        severity=RiskSeverity.HIGH_IMPACT,
        confidence=0.93,
        explanation=(
            "The memory contains a secret-like or credential-like pattern. "
            "The evidence span anchors only a non-secret label or prefix."
        ),
        recommended_disposition=RecommendedDisposition.QUARANTINE,
    )


def _sentence_spans(text: str) -> tuple[tuple[str, int, int], ...]:
    spans: list[tuple[str, int, int]] = []
    for match in re.finditer(r"[^.!?\n]{8,}[.!?]?", text):
        sentence = match.group(0).strip()
        if len(sentence) >= 8:
            start = match.start() + (len(match.group(0)) - len(match.group(0).lstrip()))
            end = start + len(sentence)
            spans.append((sentence, start, end))
    return tuple(spans)


def _detect_repetition_pattern(
    definition: DetectorDefinition, event: MemoryEvent
) -> MemoryFinding | None:
    for field in (
        EvidenceField.PROPOSED_MEMORY,
        EvidenceField.RAW_OR_REDACTED_CONTENT,
    ):
        seen: dict[str, tuple[str, int, int]] = {}
        for sentence, start, end in _sentence_spans(_event_text(event, field)):
            normalized = re.sub(r"\s+", " ", sentence.lower()).strip()
            if normalized in seen:
                return _make_finding(
                    definition,
                    event,
                    EvidenceSpan(field, start, end, sentence),
                    severity=RiskSeverity.INFORMATIONAL,
                    confidence=0.62,
                    explanation=(
                        "The memory repeats similar text, which can be a sign of "
                        "anomalous persistence or over-consolidation."
                    ),
                    recommended_disposition=RecommendedDisposition.WARN,
                    limitations=("Exact repeated sentence heuristic only.",),
                )
            seen[normalized] = (sentence, start, end)
    return None


_DETECTOR_DEFINITIONS: tuple[DetectorDefinition, ...] = (
    DetectorDefinition(
        name="provenance-gap-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.PROVENANCE_GAP,
        description="Flags memories with unknown or untrusted declared source authority.",
        limitations=(
            "Uses declared event authority only.",
            "Does not verify the source outside the supplied event.",
        ),
    ),
    DetectorDefinition(
        name="instruction-pattern-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.INSTRUCTION_INJECTION,
        description="Flags instruction-like text that may persist behavior changes.",
        limitations=(
            "Pattern heuristic only.",
            "Does not prove adversarial intent or universal prompt injection.",
        ),
    ),
    DetectorDefinition(
        name="authority-change-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.AUTHORITY_OR_IDENTITY_CHANGE,
        description="Flags authority, ownership, approval, payment, or access changes.",
        limitations=(
            "Keyword heuristic only.",
            "Requires domain-specific validation before action.",
        ),
    ),
    DetectorDefinition(
        name="stale-temporal-state-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.TEMPORAL_OR_STALE_STATE,
        description="Flags dated or temporal state that may become stale.",
        limitations=(
            "Uses supplied event timestamp and local text only.",
            "Does not check live source-of-record freshness.",
        ),
    ),
    DetectorDefinition(
        name="scope-privacy-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.SCOPE_OR_PRIVACY_VIOLATION,
        description="Flags privacy-sensitive or cross-scope memory text.",
        limitations=(
            "Pattern heuristic only.",
            "Does not replace a full privacy or tenancy policy.",
        ),
    ),
    DetectorDefinition(
        name="secret-pattern-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.SCOPE_OR_PRIVACY_VIOLATION,
        description="Flags secret-like, credential-like, or payment-card-like text.",
        limitations=(
            "Pattern heuristic only.",
            "Does not guarantee complete secret detection.",
            "Evidence span intentionally avoids quoting the full matched secret.",
        ),
    ),
    DetectorDefinition(
        name="repetition-pattern-v1",
        version=DETECTOR_VERSION,
        risk_category=RiskCategory.ANOMALOUS_PERSISTENCE,
        description="Flags repeated sentence-like text in one event.",
        limitations=(
            "Exact repeated sentence heuristic only.",
            "Does not judge whether repetition is intentional.",
        ),
    ),
)

_DETECTOR_DEFINITION_BY_NAME: dict[str, DetectorDefinition] = {
    definition.name: definition for definition in _DETECTOR_DEFINITIONS
}

_DETECTOR_FUNCTIONS: dict[str, DetectorFn] = {
    "provenance-gap-v1": _detect_provenance_gap,
    "instruction-pattern-v1": _detect_instruction_pattern,
    "authority-change-v1": _detect_authority_change,
    "stale-temporal-state-v1": _detect_stale_temporal_state,
    "scope-privacy-v1": _detect_scope_privacy,
    "secret-pattern-v1": _detect_secret_pattern,
    "repetition-pattern-v1": _detect_repetition_pattern,
}
