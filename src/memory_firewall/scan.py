"""Streaming scan and watch helpers for normalized memory events."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, TextIO

from .analysis import (
    MemoryStateAssertion,
    StateAnalysisResult,
    TrustedStateAction,
    analyze_memory_state,
)
from .detectors import DetectorResult, run_detectors
from .models import MemoryEvent, RecommendedDisposition, SourceAuthority
from .policy import max_disposition

SCAN_VERSION = "mf-06"
SCAN_ISSUE_ID_PREFIX = "mfissue_v1_"
DEFAULT_SCAN_CONTEXT_ASSERTIONS = 1024
SCAN_EXIT_CLEAN = 0
SCAN_EXIT_REVIEW_REQUIRED = 1
SCAN_EXIT_INVALID_INPUT = 2
SCAN_EXIT_INTERRUPTED = 130
_SCAN_CONTEXT_AUTHORITIES = frozenset(
    {
        SourceAuthority.TOOL_OBSERVED,
        SourceAuthority.SYSTEM,
        SourceAuthority.SIGNED_RECORD,
        SourceAuthority.HUMAN_APPROVED,
    }
)


class ScanEventLevel(str, Enum):
    """Compact per-event scan level for terminal and watch output."""

    PASS = "pass"
    WARN = "warn"
    HIGH_RISK = "high_risk"


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_scan_issue_id(
    *, source: str, line_number: int, error_type: str
) -> str:
    """Return a deterministic issue id without hashing raw input content."""

    digest = hashlib.sha256(
        _canonical_json(
            {
                "source": source,
                "line_number": line_number,
                "error_type": error_type,
            }
        ).encode("utf-8")
    ).hexdigest()
    return f"{SCAN_ISSUE_ID_PREFIX}{digest[:32]}"


@dataclass(frozen=True, slots=True)
class ScanIssue:
    """Structured scan issue for an invalid JSONL line."""

    issue_id: str
    line_number: int
    error_type: str
    message: str

    def __post_init__(self) -> None:
        if not self.issue_id.startswith(SCAN_ISSUE_ID_PREFIX):
            raise ValueError(f"issue_id must start with {SCAN_ISSUE_ID_PREFIX}")
        if self.line_number < 1:
            raise ValueError("line_number must be positive")
        if not self.error_type:
            raise ValueError("error_type must not be empty")
        if not self.message:
            raise ValueError("message must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable issue."""

        return {
            "issue_id": self.issue_id,
            "line_number": self.line_number,
            "error_type": self.error_type,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ScanEventResult:
    """Scan output for one valid MemoryEvent JSONL line."""

    line_number: int
    event_id: str
    level: ScanEventLevel
    highest_disposition: RecommendedDisposition
    detector_result: DetectorResult
    state_analysis: StateAnalysisResult

    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be positive")
        if not self.event_id:
            raise ValueError("event_id must not be empty")
        if not isinstance(self.level, ScanEventLevel):
            raise TypeError("level must be a ScanEventLevel")
        if not isinstance(self.highest_disposition, RecommendedDisposition):
            raise TypeError("highest_disposition must be a RecommendedDisposition")
        if not isinstance(self.detector_result, DetectorResult):
            raise TypeError("detector_result must be a DetectorResult")
        if not isinstance(self.state_analysis, StateAnalysisResult):
            raise TypeError("state_analysis must be a StateAnalysisResult")
        if self.detector_result.event_id != self.event_id:
            raise ValueError("detector_result event_id must match event_id")
        if self.state_analysis.event_id != self.event_id:
            raise ValueError("state_analysis event_id must match event_id")

    @property
    def finding_count(self) -> int:
        """Return the number of detector findings for this event."""

        return len(self.detector_result.findings)

    @property
    def contradiction_count(self) -> int:
        """Return the number of state-analysis contradictions."""

        return len(self.state_analysis.contradictions)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable event scan result."""

        return {
            "line_number": self.line_number,
            "event_id": self.event_id,
            "level": self.level.value,
            "highest_disposition": self.highest_disposition.value,
            "finding_count": self.finding_count,
            "contradiction_count": self.contradiction_count,
            "detector_result": self.detector_result.to_dict(),
            "state_analysis": self.state_analysis.to_dict(),
        }


ScanRecord = ScanEventResult | ScanIssue


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Deterministic aggregate counts for a scan/watch run."""

    total_lines: int
    analyzed_events: int
    invalid_lines: int
    pass_events: int
    warn_events: int
    high_risk_events: int
    total_findings: int
    blocked_low_authority_contradictions: int
    highest_disposition: RecommendedDisposition

    def __post_init__(self) -> None:
        for field_name in (
            "total_lines",
            "analyzed_events",
            "invalid_lines",
            "pass_events",
            "warn_events",
            "high_risk_events",
            "total_findings",
            "blocked_low_authority_contradictions",
        ):
            value = getattr(self, field_name)
            if value < 0:
                raise ValueError(f"{field_name} must be non-negative")
        if self.total_lines != self.analyzed_events + self.invalid_lines:
            raise ValueError("total_lines must equal analyzed_events + invalid_lines")
        if self.analyzed_events != (
            self.pass_events + self.warn_events + self.high_risk_events
        ):
            raise ValueError("event level counts must equal analyzed_events")
        if not isinstance(self.highest_disposition, RecommendedDisposition):
            raise TypeError("highest_disposition must be a RecommendedDisposition")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary."""

        return {
            "total_lines": self.total_lines,
            "analyzed_events": self.analyzed_events,
            "invalid_lines": self.invalid_lines,
            "pass_events": self.pass_events,
            "warn_events": self.warn_events,
            "high_risk_events": self.high_risk_events,
            "total_findings": self.total_findings,
            "blocked_low_authority_contradictions": (
                self.blocked_low_authority_contradictions
            ),
            "highest_disposition": self.highest_disposition.value,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Completed scan result over a finite JSONL event stream."""

    scan_version: str
    source: str
    summary: ScanSummary
    events: tuple[ScanEventResult, ...]
    issues: tuple[ScanIssue, ...]
    metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.scan_version != SCAN_VERSION:
            raise ValueError(f"scan_version must be {SCAN_VERSION}")
        if not self.source:
            raise ValueError("source must not be empty")
        if not isinstance(self.summary, ScanSummary):
            raise TypeError("summary must be a ScanSummary")
        if any(not isinstance(item, ScanEventResult) for item in self.events):
            raise TypeError("events must contain ScanEventResult objects")
        if any(not isinstance(item, ScanIssue) for item in self.issues):
            raise TypeError("issues must contain ScanIssue objects")
        metadata = {} if self.metadata is None else dict(self.metadata)
        object.__setattr__(self, "metadata", MappingProxyType(metadata))

    def to_dict(self, *, include_events: bool = True) -> dict[str, Any]:
        """Return a JSON-serializable scan result."""

        return {
            "scan_version": self.scan_version,
            "source": self.source,
            "summary": self.summary.to_dict(),
            "events": [item.to_dict() for item in self.events] if include_events else [],
            "issues": [item.to_dict() for item in self.issues],
            "metadata": dict({} if self.metadata is None else self.metadata),
        }


def _generic_issue(line_number: int, source: str, exc: Exception) -> ScanIssue:
    error_type = exc.__class__.__name__
    return ScanIssue(
        issue_id=compute_scan_issue_id(
            source=source,
            line_number=line_number,
            error_type=error_type,
        ),
        line_number=line_number,
        error_type=error_type,
        message="line could not be parsed as a valid MemoryEvent",
    )


def _parse_event_line(line: str) -> MemoryEvent:
    payload = json.loads(line)
    if not isinstance(payload, Mapping):
        raise TypeError("MemoryEvent JSONL line must be an object")
    return MemoryEvent.from_dict(payload)


def _highest_disposition(detector_result: DetectorResult) -> RecommendedDisposition:
    disposition = RecommendedDisposition.PASS
    for recommendation in detector_result.policy_recommendations:
        disposition = max_disposition(
            disposition,
            recommendation.recommended_disposition,
        )
    return disposition


def _event_level(
    disposition: RecommendedDisposition,
    analysis: StateAnalysisResult,
) -> ScanEventLevel:
    if (
        analysis.trusted_state_action
        == TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
    ):
        return ScanEventLevel.HIGH_RISK
    if disposition in {
        RecommendedDisposition.REVIEW,
        RecommendedDisposition.QUARANTINE,
    }:
        return ScanEventLevel.HIGH_RISK
    if disposition == RecommendedDisposition.WARN:
        return ScanEventLevel.WARN
    return ScanEventLevel.PASS


def scan_event(
    event: MemoryEvent,
    *,
    line_number: int = 1,
    existing_assertions: tuple[MemoryStateAssertion, ...] = (),
) -> ScanEventResult:
    """Run detectors, policy, and state analysis for one event."""

    detector_result = run_detectors(event)
    analysis = analyze_memory_state(
        event,
        detector_result=detector_result,
        existing_assertions=existing_assertions,
    )
    disposition = _highest_disposition(detector_result)
    return ScanEventResult(
        line_number=line_number,
        event_id=event.event_id,
        level=_event_level(disposition, analysis),
        highest_disposition=disposition,
        detector_result=detector_result,
        state_analysis=analysis,
    )


def iter_scan_records(
    lines: Iterable[str],
    *,
    source: str = "<stream>",
    existing_assertions: tuple[MemoryStateAssertion, ...] = (),
    max_context_assertions: int = DEFAULT_SCAN_CONTEXT_ASSERTIONS,
) -> Iterable[ScanRecord]:
    """Yield scan records while reading a JSONL stream line by line."""

    if max_context_assertions < 0:
        raise ValueError("max_context_assertions must be non-negative")
    assertions_by_key: OrderedDict[tuple[str, str], MemoryStateAssertion] = OrderedDict()
    for assertion in existing_assertions:
        assertions_by_key[assertion.conflict_key] = assertion
        while len(assertions_by_key) > max_context_assertions:
            assertions_by_key.popitem(last=False)
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        try:
            event = _parse_event_line(line)
            result = scan_event(
                event,
                line_number=line_number,
                existing_assertions=tuple(assertions_by_key.values()),
            )
        except Exception as exc:
            yield _generic_issue(line_number, source, exc)
            continue
        if max_context_assertions and _can_seed_scan_context(result):
            assertions_by_key[result.state_analysis.assertion.conflict_key] = (
                result.state_analysis.assertion
            )
            assertions_by_key.move_to_end(result.state_analysis.assertion.conflict_key)
            while len(assertions_by_key) > max_context_assertions:
                assertions_by_key.popitem(last=False)
        yield result


def _can_seed_scan_context(result: ScanEventResult) -> bool:
    assertion = result.state_analysis.assertion
    return (
        result.level == ScanEventLevel.PASS
        and result.state_analysis.trusted_state_action
        == TrustedStateAction.CANDIDATE_ONLY
        and assertion.source_authority in _SCAN_CONTEXT_AUTHORITIES
    )


def scan_jsonl_events(
    lines: Iterable[str],
    *,
    source: str = "<stream>",
    existing_assertions: tuple[MemoryStateAssertion, ...] = (),
    include_events: bool = True,
    max_context_assertions: int = DEFAULT_SCAN_CONTEXT_ASSERTIONS,
) -> ScanResult:
    """Scan a finite JSONL stream of MemoryEvent objects."""

    total_lines = 0
    analyzed_events = 0
    invalid_lines = 0
    pass_events = 0
    warn_events = 0
    high_risk_events = 0
    total_findings = 0
    blocked_low_authority_contradictions = 0
    highest_disposition = RecommendedDisposition.PASS
    events: list[ScanEventResult] = []
    issues: list[ScanIssue] = []

    for record in iter_scan_records(
        lines,
        source=source,
        existing_assertions=existing_assertions,
        max_context_assertions=max_context_assertions,
    ):
        total_lines += 1
        if isinstance(record, ScanIssue):
            invalid_lines += 1
            issues.append(record)
            continue
        analyzed_events += 1
        total_findings += record.finding_count
        highest_disposition = max_disposition(
            highest_disposition,
            record.highest_disposition,
        )
        if (
            record.state_analysis.trusted_state_action
            == TrustedStateAction.BLOCKED_LOW_AUTHORITY_CONTRADICTION
        ):
            blocked_low_authority_contradictions += 1
        if record.level == ScanEventLevel.PASS:
            pass_events += 1
        elif record.level == ScanEventLevel.WARN:
            warn_events += 1
        else:
            high_risk_events += 1
        if include_events:
            events.append(record)

    summary = ScanSummary(
        total_lines=total_lines,
        analyzed_events=analyzed_events,
        invalid_lines=invalid_lines,
        pass_events=pass_events,
        warn_events=warn_events,
        high_risk_events=high_risk_events,
        total_findings=total_findings,
        blocked_low_authority_contradictions=blocked_low_authority_contradictions,
        highest_disposition=highest_disposition,
    )
    return ScanResult(
        scan_version=SCAN_VERSION,
        source=source,
        summary=summary,
        events=tuple(events),
        issues=tuple(issues),
        metadata={
            "line_oriented": True,
            "input_contract": "MemoryEvent JSONL",
            "state_scope": "bounded_review_eligible_scan_context_only",
            "max_context_assertions": max_context_assertions,
        },
    )


def exit_code_for_summary(summary: ScanSummary) -> int:
    """Return deterministic process exit code for a scan/watch summary."""

    if summary.invalid_lines:
        return SCAN_EXIT_INVALID_INPUT
    if summary.high_risk_events:
        return SCAN_EXIT_REVIEW_REQUIRED
    return SCAN_EXIT_CLEAN


def _record_json_line(record: ScanRecord) -> dict[str, Any]:
    if isinstance(record, ScanIssue):
        return {
            "scan_version": SCAN_VERSION,
            "record_type": "issue",
            "issue": record.to_dict(),
        }
    return {
        "scan_version": SCAN_VERSION,
        "record_type": "event",
        "event": record.to_dict(),
    }


def _print_watch_record(record: ScanRecord, stdout: TextIO, *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(_record_json_line(record), sort_keys=True),
            file=stdout,
            flush=True,
        )
        return
    if isinstance(record, ScanIssue):
        print(
            f"INVALID line={record.line_number} issue={record.issue_id}",
            file=stdout,
            flush=True,
        )
        return
    level = record.level.value.replace("_", "-").upper()
    print(
        f"{level} line={record.line_number} "
        f"event={record.event_id} findings={record.finding_count} "
        f"disposition={record.highest_disposition.value}",
        file=stdout,
        flush=True,
    )


def watch_stdin_events(
    lines: Iterable[str],
    stdout: TextIO,
    *,
    as_json: bool = True,
    source: str = "<stdin>",
    existing_assertions: tuple[MemoryStateAssertion, ...] = (),
    max_context_assertions: int = DEFAULT_SCAN_CONTEXT_ASSERTIONS,
) -> int:
    """Watch a stdin-like JSONL stream and emit one result per input line."""

    exit_code = SCAN_EXIT_CLEAN
    try:
        for record in iter_scan_records(
            lines,
            source=source,
            existing_assertions=existing_assertions,
            max_context_assertions=max_context_assertions,
        ):
            _print_watch_record(record, stdout, as_json=as_json)
            if isinstance(record, ScanIssue):
                exit_code = max(exit_code, SCAN_EXIT_INVALID_INPUT)
            elif record.level == ScanEventLevel.HIGH_RISK:
                exit_code = max(exit_code, SCAN_EXIT_REVIEW_REQUIRED)
    except KeyboardInterrupt:
        payload = {"scan_version": SCAN_VERSION, "record_type": "interrupted"}
        if as_json:
            print(json.dumps(payload, sort_keys=True), file=stdout, flush=True)
        else:
            print("INTERRUPTED", file=stdout, flush=True)
        return SCAN_EXIT_INTERRUPTED
    return exit_code
