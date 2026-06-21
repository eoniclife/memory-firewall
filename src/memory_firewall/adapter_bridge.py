"""Generic local adapter bridge for one memory candidate at a time."""

from __future__ import annotations

import html
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

from .detectors import default_detector_pack
from .models import (
    JSONScalar,
    MemoryEvent,
    MemoryOperation,
    RFC3339_TIMESTAMP_PATTERN,
    RecommendedDisposition,
    RiskCategory,
    SourceAuthority,
    SourceType,
)
from .scan import ScanEventLevel, ScanEventResult, scan_event
from .version import __version__

ADAPTER_BRIDGE_VERSION = "mf-22"
ADAPTER_BRIDGE_REPORT_VERSION = "mf-22"
ADAPTER_BRIDGE_DIR_ENV = "MEMORY_FIREWALL_ADAPTER_DIR"
ADAPTER_BRIDGE_EVENTS_FILENAME = "events.jsonl"
ADAPTER_BRIDGE_OBSERVATIONS_FILENAME = "observations.jsonl"
ADAPTER_BRIDGE_REPORT_JSON_FILENAME = "report.json"
ADAPTER_BRIDGE_REPORT_HTML_FILENAME = "index.html"
ADAPTER_BRIDGE_REDACTED_EXPORT_FILENAME = "redacted-share.json"
ADAPTER_BRIDGE_STATE_DIR_MODE = 0o700
ADAPTER_BRIDGE_STATE_FILE_MODE = 0o600
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PUBLIC_LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,63}$")
_PUBLIC_BRIDGE_VERSION_RE = re.compile(r"^mf-[0-9]{1,4}$")
_SECRETISH_TOKEN_RE = re.compile(
    r"(?i)(^sk-[A-Za-z0-9_-]{8,}|^ghp_[A-Za-z0-9_]{12,}|"
    r"^xox[baprs]-[A-Za-z0-9-]{8,}|token|secret|password|api[_-]?key|bearer)"
)
_RFC3339_TIMESTAMP_RE = re.compile(RFC3339_TIMESTAMP_PATTERN)
_PUBLIC_TARGET_NAMESPACES = frozenset(
    (
        "crm",
        "diagnostics",
        "facts",
        "global",
        "local",
        "memory",
        "notes",
        "preferences",
        "profile",
        "project",
        "semantic",
        "session",
        "system",
        "tool",
        "user",
    )
)
_RISK_CATEGORIES = frozenset(item.value for item in RiskCategory)
_PUBLIC_DETECTOR_NAMES = frozenset(
    definition.name for definition in default_detector_pack().definitions
)
_PUBLIC_DIAGNOSTIC_DETECTOR_NAMES = frozenset(
    (
        "diagnostic-invalid-json",
        "diagnostic-non-object-json",
    )
)
_ADAPTER_REPORT_STATUSES = frozenset(("ready", "empty", "attention"))


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def default_adapter_bridge_state_dir() -> Path:
    """Return the local diagnostics directory for generic adapter observations."""

    override = os.environ.get(ADAPTER_BRIDGE_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".memory-firewall" / "adapter"


def _resolve_state_dir(state_dir: str | Path | None = None) -> Path:
    if state_dir is not None:
        return Path(state_dir).expanduser()
    return default_adapter_bridge_state_dir()


def _ensure_private_state_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True, mode=ADAPTER_BRIDGE_STATE_DIR_MODE)
    current_mode = stat.S_IMODE(output_dir.stat().st_mode)
    if current_mode != ADAPTER_BRIDGE_STATE_DIR_MODE:
        output_dir.chmod(ADAPTER_BRIDGE_STATE_DIR_MODE)


def _append_private_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if isinstance(nofollow, int):
        flags |= nofollow
    fd = os.open(path, flags, ADAPTER_BRIDGE_STATE_FILE_MODE)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != ADAPTER_BRIDGE_STATE_FILE_MODE:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, ADAPTER_BRIDGE_STATE_FILE_MODE)
            else:
                path.chmod(ADAPTER_BRIDGE_STATE_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    finally:
        if fd >= 0:
            os.close(fd)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                rows.append(_diagnostic_row(line_number, "invalid-json"))
                continue
            if isinstance(payload, dict):
                rows.append(payload)
            else:
                rows.append(_diagnostic_row(line_number, "non-object-json"))
    return rows


def _safe_target_namespace(value: object) -> str:
    if (
        isinstance(value, str)
        and _SAFE_TARGET_RE.fullmatch(value)
        and value in _PUBLIC_TARGET_NAMESPACES
    ):
        return value
    return "redacted-target"


def _safe_public_label(value: object, *, default: str) -> str:
    if (
        isinstance(value, str)
        and _PUBLIC_LABEL_RE.fullmatch(value)
        and not _SECRETISH_TOKEN_RE.search(value)
    ):
        return value
    return default


def _safe_bridge_version(value: object) -> str:
    if isinstance(value, str) and _PUBLIC_BRIDGE_VERSION_RE.fullmatch(value):
        return value
    return "unknown-version"


def _safe_recorded_at(value: object) -> str:
    if isinstance(value, str) and _RFC3339_TIMESTAMP_RE.fullmatch(value):
        return value
    return "unavailable-recorded-at"


def _enum_value(value: object, *, allowed: frozenset[str], default: str) -> str:
    return value if isinstance(value, str) and value in allowed else default


def _findings_from_scan_payload(
    scan_payload: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    detector_result = scan_payload.get("detector_result")
    if not isinstance(detector_result, Mapping):
        return ()
    findings = detector_result.get("findings")
    if not isinstance(findings, list):
        return ()
    return tuple(item for item in findings if isinstance(item, Mapping))


def _tuple_field_from_findings(
    findings: tuple[Mapping[str, Any], ...],
    field_name: str,
) -> tuple[str, ...]:
    values: set[str] = set()
    for item in findings:
        raw = item.get(field_name)
        if not isinstance(raw, str) or not raw:
            continue
        if field_name == "risk_category":
            if raw in _RISK_CATEGORIES:
                values.add(raw)
        elif field_name == "detector_name":
            if raw in _PUBLIC_DETECTOR_NAMES or raw in _PUBLIC_DIAGNOSTIC_DETECTOR_NAMES:
                values.add(raw)
            else:
                values.add("redacted-detector")
        else:
            values.add("redacted-value")
    return tuple(sorted(values))


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    return 0


def _diagnostic_row(line_number: int, error_type: str) -> dict[str, Any]:
    detector_name = (
        "diagnostic-invalid-json"
        if error_type == "invalid-json"
        else "diagnostic-non-object-json"
    )
    return {
        "bridge_version": ADAPTER_BRIDGE_VERSION,
        "recorded_at": "unavailable-recorded-at",
        "adapter_name": "diagnostics",
        "event": {
            "operation": MemoryOperation.UPSERT.value,
            "source_authority": SourceAuthority.UNTRUSTED.value,
            "target_namespace": "diagnostics",
        },
        "scan": {
            "level": ScanEventLevel.WARN.value,
            "highest_disposition": RecommendedDisposition.REVIEW.value,
            "finding_count": 1,
            "contradiction_count": 0,
            "detector_result": {
                "findings": [
                    {
                        "risk_category": RiskCategory.ANOMALOUS_PERSISTENCE.value,
                        "detector_name": detector_name,
                        "line_number": line_number,
                    }
                ]
            },
        },
    }


@dataclass(frozen=True, slots=True)
class AdapterBridgeObservation:
    """One persisted generic adapter observation."""

    bridge_version: str
    recorded_at: str
    adapter_name: str
    event: MemoryEvent
    scan: ScanEventResult

    def __post_init__(self) -> None:
        if self.bridge_version != ADAPTER_BRIDGE_VERSION:
            raise ValueError(f"bridge_version must be {ADAPTER_BRIDGE_VERSION}")
        if not self.recorded_at:
            raise ValueError("recorded_at must not be empty")
        if not self.adapter_name:
            raise ValueError("adapter_name must not be empty")
        if not isinstance(self.event, MemoryEvent):
            raise TypeError("event must be MemoryEvent")
        if not isinstance(self.scan, ScanEventResult):
            raise TypeError("scan must be ScanEventResult")
        if self.scan.event_id != self.event.event_id:
            raise ValueError("scan event_id must match event event_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bridge_version": self.bridge_version,
            "recorded_at": self.recorded_at,
            "adapter_name": self.adapter_name,
            "event": self.event.to_dict(),
            "scan": self.scan.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeObservationSummary:
    """Redacted summary of a generic adapter observation."""

    bridge_version: str
    recorded_bridge_version: str
    row_number: int
    recorded_at: str
    adapter_name: str
    event_ref: str
    operation: str
    source_authority: str
    target_namespace: str
    level: str
    highest_disposition: str
    finding_count: int
    contradiction_count: int
    risk_categories: tuple[str, ...]
    detector_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.bridge_version != ADAPTER_BRIDGE_VERSION:
            raise ValueError(f"bridge_version must be {ADAPTER_BRIDGE_VERSION}")
        for field_name in (
            "recorded_bridge_version",
            "recorded_at",
            "adapter_name",
            "event_ref",
            "operation",
            "source_authority",
            "target_namespace",
            "level",
            "highest_disposition",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must not be empty")
        if not isinstance(self.row_number, int) or self.row_number < 1:
            raise ValueError("row_number must be positive")
        for field_name in ("finding_count", "contradiction_count"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        for field_name in ("risk_categories", "detector_names"):
            value = getattr(self, field_name)
            if isinstance(value, str) or not isinstance(value, tuple):
                raise TypeError(f"{field_name} must be a tuple")
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError(f"{field_name} must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bridge_version": self.bridge_version,
            "recorded_bridge_version": self.recorded_bridge_version,
            "row_number": self.row_number,
            "recorded_at": self.recorded_at,
            "adapter_name": self.adapter_name,
            "event_ref": self.event_ref,
            "operation": self.operation,
            "source_authority": self.source_authority,
            "target_namespace": self.target_namespace,
            "level": self.level,
            "highest_disposition": self.highest_disposition,
            "finding_count": self.finding_count,
            "contradiction_count": self.contradiction_count,
            "risk_categories": list(self.risk_categories),
            "detector_names": list(self.detector_names),
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeObservationList:
    """Newest-first redacted generic adapter observations."""

    bridge_version: str
    state_dir: str
    limit: int
    total_observations: int
    high_risk_observations: int
    warn_observations: int
    pass_observations: int
    returned_observations: int
    observations: tuple[AdapterBridgeObservationSummary, ...]

    def __post_init__(self) -> None:
        if self.bridge_version != ADAPTER_BRIDGE_VERSION:
            raise ValueError(f"bridge_version must be {ADAPTER_BRIDGE_VERSION}")
        if not self.state_dir:
            raise ValueError("state_dir must not be empty")
        for field_name in (
            "limit",
            "total_observations",
            "high_risk_observations",
            "warn_observations",
            "pass_observations",
            "returned_observations",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.limit < 1:
            raise ValueError("limit must be positive")
        if self.returned_observations != len(self.observations):
            raise ValueError("returned_observations must equal observations length")
        if self.returned_observations > self.total_observations:
            raise ValueError("returned_observations cannot exceed total_observations")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bridge_version": self.bridge_version,
            "state_dir": self.state_dir,
            "limit": self.limit,
            "total_observations": self.total_observations,
            "high_risk_observations": self.high_risk_observations,
            "warn_observations": self.warn_observations,
            "pass_observations": self.pass_observations,
            "returned_observations": self.returned_observations,
            "observations": [item.to_dict() for item in self.observations],
            "observe_only": True,
            "production_enforcement": False,
            "raw_content_included": False,
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeObserveResult:
    """Redacted result for one generic memory-candidate observation."""

    bridge_version: str
    state_dir: str
    observation: AdapterBridgeObservationSummary
    observe_only: bool = True
    production_enforcement: bool = False
    raw_content_included: bool = False

    def __post_init__(self) -> None:
        if self.bridge_version != ADAPTER_BRIDGE_VERSION:
            raise ValueError(f"bridge_version must be {ADAPTER_BRIDGE_VERSION}")
        if not self.state_dir:
            raise ValueError("state_dir must not be empty")
        if not isinstance(self.observation, AdapterBridgeObservationSummary):
            raise TypeError("observation must be AdapterBridgeObservationSummary")
        if self.observe_only is not True:
            raise ValueError("observe_only must be true")
        if self.production_enforcement is not False:
            raise ValueError("production_enforcement must be false")
        if self.raw_content_included is not False:
            raise ValueError("raw_content_included must be false")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bridge_version": self.bridge_version,
            "state_dir": self.state_dir,
            "observation": self.observation.to_dict(),
            "observe_only": self.observe_only,
            "production_enforcement": self.production_enforcement,
            "raw_content_included": self.raw_content_included,
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeReportSetup:
    """Small setup snapshot for a generic adapter diagnostics report."""

    overall_status: str
    state_dir_exists: bool
    events_file_exists: bool
    observations_file_exists: bool
    state_dir_mode: str | None
    events_file_mode: str | None
    observations_file_mode: str | None

    def __post_init__(self) -> None:
        if self.overall_status not in _ADAPTER_REPORT_STATUSES:
            raise ValueError("overall_status must be ready, empty, or attention")
        for field_name in (
            "state_dir_exists",
            "events_file_exists",
            "observations_file_exists",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")
        for field_name in (
            "state_dir_mode",
            "events_file_mode",
            "observations_file_mode",
        ):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, str) or not re.fullmatch(r"[0-7]{4}", value)
            ):
                raise ValueError(f"{field_name} must be an octal mode or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "state_dir_exists": self.state_dir_exists,
            "events_file_exists": self.events_file_exists,
            "observations_file_exists": self.observations_file_exists,
            "state_dir_mode": self.state_dir_mode,
            "events_file_mode": self.events_file_mode,
            "observations_file_mode": self.observations_file_mode,
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeReportSummary:
    """Compact counters for a generic adapter diagnostics report."""

    total_observations: int
    pass_observations: int
    warn_observations: int
    high_risk_observations: int
    returned_observations: int
    report_contains_raw_content: bool = False
    hosted_dashboard: bool = False
    production_enforcement: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "total_observations",
            "pass_observations",
            "warn_observations",
            "high_risk_observations",
            "returned_observations",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.returned_observations > self.total_observations:
            raise ValueError("returned_observations cannot exceed total_observations")
        for field_name in (
            "report_contains_raw_content",
            "hosted_dashboard",
            "production_enforcement",
        ):
            value = getattr(self, field_name)
            if value is not False:
                raise ValueError(f"{field_name} must be false")

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_observations": self.total_observations,
            "pass_observations": self.pass_observations,
            "warn_observations": self.warn_observations,
            "high_risk_observations": self.high_risk_observations,
            "returned_observations": self.returned_observations,
            "report_contains_raw_content": self.report_contains_raw_content,
            "hosted_dashboard": self.hosted_dashboard,
            "production_enforcement": self.production_enforcement,
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeReportResult:
    """Local redacted report over generic adapter diagnostics."""

    report_version: str
    bridge_version: str
    package_version: str
    title: str
    generated_at: str
    state_dir: str
    setup: AdapterBridgeReportSetup
    summary: AdapterBridgeReportSummary
    observations: AdapterBridgeObservationList
    level_counts: Mapping[str, int]
    risk_category_counts: Mapping[str, int]
    detector_counts: Mapping[str, int]
    next_steps: tuple[str, ...]
    limitations: tuple[str, ...]
    observe_only: bool = True
    production_enforcement: bool = False
    raw_content_included: bool = False

    def __post_init__(self) -> None:
        if self.report_version != ADAPTER_BRIDGE_REPORT_VERSION:
            raise ValueError(
                f"report_version must be {ADAPTER_BRIDGE_REPORT_VERSION}"
            )
        if self.bridge_version != ADAPTER_BRIDGE_VERSION:
            raise ValueError(f"bridge_version must be {ADAPTER_BRIDGE_VERSION}")
        for field_name in ("package_version", "title", "generated_at", "state_dir"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must not be empty")
        if not isinstance(self.setup, AdapterBridgeReportSetup):
            raise TypeError("setup must be AdapterBridgeReportSetup")
        if not isinstance(self.summary, AdapterBridgeReportSummary):
            raise TypeError("summary must be AdapterBridgeReportSummary")
        if not isinstance(self.observations, AdapterBridgeObservationList):
            raise TypeError("observations must be AdapterBridgeObservationList")
        for field_name in (
            "level_counts",
            "risk_category_counts",
            "detector_counts",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, Mapping):
                raise TypeError(f"{field_name} must be a mapping")
            for key, count in value.items():
                if not isinstance(key, str) or not key:
                    raise ValueError(f"{field_name} keys must be non-empty strings")
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    raise ValueError(
                        f"{field_name} values must be non-negative integers"
                    )
        for field_name in ("next_steps", "limitations"):
            value = getattr(self, field_name)
            if isinstance(value, str) or not isinstance(value, tuple):
                raise TypeError(f"{field_name} must be a tuple")
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError(f"{field_name} must contain non-empty strings")
        for field_name in (
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")
        if self.observe_only is not True:
            raise ValueError("observe_only must be true")
        if self.production_enforcement is not False:
            raise ValueError("production_enforcement must be false")
        if self.raw_content_included is not False:
            raise ValueError("raw_content_included must be false")

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report_version,
            "bridge_version": self.bridge_version,
            "package_version": self.package_version,
            "title": self.title,
            "generated_at": self.generated_at,
            "state_dir": self.state_dir,
            "setup": self.setup.to_dict(),
            "summary": self.summary.to_dict(),
            "observations": self.observations.to_dict(),
            "level_counts": dict(sorted(self.level_counts.items())),
            "risk_category_counts": dict(sorted(self.risk_category_counts.items())),
            "detector_counts": dict(sorted(self.detector_counts.items())),
            "next_steps": list(self.next_steps),
            "limitations": list(self.limitations),
            "observe_only": self.observe_only,
            "production_enforcement": self.production_enforcement,
            "raw_content_included": self.raw_content_included,
        }

    def to_redacted_share_dict(self) -> dict[str, Any]:
        observations = self.observations.to_dict()
        observations["state_dir"] = "redacted-local-path"
        return {
            "report_version": self.report_version,
            "bridge_version": self.bridge_version,
            "title": self.title,
            "generated_at": self.generated_at,
            "local_paths_redacted": True,
            "state_dir": "redacted-local-path",
            "raw_content_included": False,
            "setup": self.setup.to_dict(),
            "summary": self.summary.to_dict(),
            "observations": observations,
            "level_counts": dict(sorted(self.level_counts.items())),
            "risk_category_counts": dict(sorted(self.risk_category_counts.items())),
            "detector_counts": dict(sorted(self.detector_counts.items())),
            "next_steps_present": bool(self.next_steps),
            "limitations": list(self.limitations),
            "observe_only": True,
            "production_enforcement": False,
        }


@dataclass(frozen=True, slots=True)
class AdapterBridgeReportBundle:
    """Files written for a local generic adapter diagnostics report bundle."""

    report: AdapterBridgeReportResult
    output_dir: Path
    report_json_path: Path
    html_path: Path
    redacted_export_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report.report_version,
            "bridge_version": self.report.bridge_version,
            "title": self.report.title,
            "summary": self.report.summary.to_dict(),
            "setup": self.report.setup.to_dict(),
            "files": {
                "paths_redacted": True,
                "report_json": self.report_json_path.name,
                "html": self.html_path.name,
                "redacted_export": self.redacted_export_path.name,
            },
            "observe_only": True,
            "production_enforcement": False,
            "raw_content_included": False,
        }


def memory_event_from_adapter_candidate(
    *,
    content: str,
    target_namespace: str = "memory",
    actor: str = "agent:local",
    user_or_tenant_scope: str = "local",
    source_type: SourceType = SourceType.UNKNOWN,
    source_id: str = "adapter-bridge",
    source_authority: SourceAuthority = SourceAuthority.UNTRUSTED,
    operation: MemoryOperation = MemoryOperation.CREATE,
    timestamp: str | None = None,
    metadata: Mapping[str, JSONScalar] | None = None,
) -> MemoryEvent:
    """Normalize one simple memory candidate into a canonical MemoryEvent."""

    return MemoryEvent.from_adapter_payload(
        {
            "timestamp": timestamp or _utc_timestamp(),
            "actor": actor,
            "user_or_tenant_scope": user_or_tenant_scope,
            "source_type": source_type.value,
            "source_id": source_id,
            "source_authority": source_authority.value,
            "raw_or_redacted_content": content,
            "proposed_memory": content,
            "operation": operation.value,
            "target_namespace": target_namespace,
            "metadata": {
                **dict(metadata or {}),
                "adapter_bridge_version": ADAPTER_BRIDGE_VERSION,
            },
        }
    )


def scan_adapter_candidate(
    event: MemoryEvent,
    *,
    adapter_name: str = "local-adapter",
    recorded_at: str | None = None,
) -> AdapterBridgeObservation:
    """Scan one normalized candidate and wrap it as a local observation."""

    return AdapterBridgeObservation(
        bridge_version=ADAPTER_BRIDGE_VERSION,
        recorded_at=recorded_at or _utc_timestamp(),
        adapter_name=adapter_name,
        event=event,
        scan=scan_event(event),
    )


def append_adapter_observation(
    observation: AdapterBridgeObservation,
    *,
    state_dir: str | Path | None = None,
) -> None:
    """Append one generic adapter observation and its normalized event."""

    output_dir = _resolve_state_dir(state_dir)
    _ensure_private_state_dir(output_dir)
    _append_private_jsonl(
        output_dir / ADAPTER_BRIDGE_EVENTS_FILENAME,
        observation.event.to_dict(),
    )
    _append_private_jsonl(
        output_dir / ADAPTER_BRIDGE_OBSERVATIONS_FILENAME,
        observation.to_dict(),
    )


def _summary_from_row(
    row: Mapping[str, Any],
    *,
    row_number: int,
) -> AdapterBridgeObservationSummary:
    raw_scan_payload = row.get("scan")
    raw_event_payload = row.get("event")
    scan_payload: Mapping[str, Any] = (
        cast(Mapping[str, Any], raw_scan_payload)
        if isinstance(raw_scan_payload, Mapping)
        else {}
    )
    event_payload: Mapping[str, Any] = (
        cast(Mapping[str, Any], raw_event_payload)
        if isinstance(raw_event_payload, Mapping)
        else {}
    )
    findings = _findings_from_scan_payload(scan_payload)
    return AdapterBridgeObservationSummary(
        bridge_version=ADAPTER_BRIDGE_VERSION,
        recorded_bridge_version=_safe_bridge_version(row.get("bridge_version")),
        row_number=row_number,
        recorded_at=_safe_recorded_at(row.get("recorded_at")),
        adapter_name=_safe_public_label(
            row.get("adapter_name"),
            default="unknown-adapter",
        ),
        event_ref=f"adapter-observation-row-{row_number}",
        operation=_enum_value(
            event_payload.get("operation"),
            allowed=frozenset(item.value for item in MemoryOperation),
            default=MemoryOperation.UPSERT.value,
        ),
        source_authority=_enum_value(
            event_payload.get("source_authority"),
            allowed=frozenset(item.value for item in SourceAuthority),
            default=SourceAuthority.UNTRUSTED.value,
        ),
        target_namespace=_safe_target_namespace(event_payload.get("target_namespace")),
        level=_enum_value(
            scan_payload.get("level"),
            allowed=frozenset(item.value for item in ScanEventLevel),
            default=ScanEventLevel.WARN.value,
        ),
        highest_disposition=_enum_value(
            scan_payload.get("highest_disposition"),
            allowed=frozenset(item.value for item in RecommendedDisposition),
            default=RecommendedDisposition.REVIEW.value,
        ),
        finding_count=_non_negative_int(scan_payload.get("finding_count")),
        contradiction_count=_non_negative_int(scan_payload.get("contradiction_count")),
        risk_categories=_tuple_field_from_findings(findings, "risk_category"),
        detector_names=_tuple_field_from_findings(findings, "detector_name"),
    )


def load_adapter_observations(
    *,
    state_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load persisted generic adapter observations."""

    output_dir = _resolve_state_dir(state_dir)
    return _load_jsonl(output_dir / ADAPTER_BRIDGE_OBSERVATIONS_FILENAME)


def recent_adapter_observations(
    *,
    state_dir: str | Path | None = None,
    limit: int = 20,
) -> AdapterBridgeObservationList:
    """Return newest-first redacted generic adapter observations."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    output_dir = _resolve_state_dir(state_dir)
    rows = load_adapter_observations(state_dir=output_dir)
    summaries = tuple(
        _summary_from_row(row, row_number=index)
        for index, row in enumerate(rows, start=1)
    )
    recent = tuple(reversed(summaries[-limit:]))
    return AdapterBridgeObservationList(
        bridge_version=ADAPTER_BRIDGE_VERSION,
        state_dir=str(output_dir),
        limit=limit,
        total_observations=len(rows),
        high_risk_observations=sum(
            1 for item in summaries if item.level == ScanEventLevel.HIGH_RISK.value
        ),
        warn_observations=sum(
            1 for item in summaries if item.level == ScanEventLevel.WARN.value
        ),
        pass_observations=sum(
            1 for item in summaries if item.level == ScanEventLevel.PASS.value
        ),
        returned_observations=len(recent),
        observations=recent,
    )


def _octal_mode(path: Path) -> str | None:
    if not path.exists():
        return None
    return oct(stat.S_IMODE(path.stat().st_mode)).replace("0o", "").zfill(4)


def _count_observation_fields(
    observations: tuple[AdapterBridgeObservationSummary, ...],
    field_name: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in observations:
        value = getattr(item, field_name)
        values: tuple[str, ...]
        if isinstance(value, str):
            values = (value,)
        elif isinstance(value, tuple):
            values = value
        else:
            values = ()
        for raw in values:
            if not isinstance(raw, str) or not raw:
                continue
            counts[raw] = counts.get(raw, 0) + 1
    return counts


def _adapter_report_setup(
    *,
    state_dir: Path,
    observations: AdapterBridgeObservationList,
) -> AdapterBridgeReportSetup:
    events_path = state_dir / ADAPTER_BRIDGE_EVENTS_FILENAME
    observations_path = state_dir / ADAPTER_BRIDGE_OBSERVATIONS_FILENAME
    if observations.high_risk_observations > 0:
        overall_status = "attention"
    elif observations.total_observations == 0:
        overall_status = "empty"
    else:
        overall_status = "ready"
    return AdapterBridgeReportSetup(
        overall_status=overall_status,
        state_dir_exists=state_dir.exists(),
        events_file_exists=events_path.exists(),
        observations_file_exists=observations_path.exists(),
        state_dir_mode=_octal_mode(state_dir),
        events_file_mode=_octal_mode(events_path),
        observations_file_mode=_octal_mode(observations_path),
    )


def _adapter_report_next_steps(
    *,
    observations: AdapterBridgeObservationList,
    limit: int,
) -> tuple[str, ...]:
    steps: list[str] = []
    if observations.total_observations == 0:
        steps.append(
            "Run `memory-firewall adapter observe-memory --content ... --target "
            "memory` from the agent or script that is about to write memory."
        )
    elif observations.high_risk_observations > 0:
        inspection_limit = max(limit, observations.total_observations)
        steps.append(
            "Inspect high-risk local rows with "
            f"`memory-firewall adapter observations --limit {inspection_limit}` "
            "before "
            "trusting those remembered facts."
        )
    elif observations.warn_observations > 0:
        steps.append(
            "Review WARN rows for provenance gaps or malformed diagnostics, then "
            "reopen this report after another meaningful memory write."
        )
    else:
        steps.append(
            "Keep the observe-only bridge around the memory write path and reopen "
            "this report after meaningful agent memory activity."
        )
    return tuple(dict.fromkeys(steps))


def generate_adapter_report(
    *,
    state_dir: str | Path | None = None,
    limit: int = 50,
) -> AdapterBridgeReportResult:
    """Generate a local redacted diagnostics report over generic observations."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    output_dir = _resolve_state_dir(state_dir)
    observations = recent_adapter_observations(state_dir=output_dir, limit=limit)
    all_rows = load_adapter_observations(state_dir=output_dir)
    all_summaries = tuple(
        _summary_from_row(row, row_number=index)
        for index, row in enumerate(all_rows, start=1)
    )
    setup = _adapter_report_setup(state_dir=output_dir, observations=observations)
    summary = AdapterBridgeReportSummary(
        total_observations=observations.total_observations,
        pass_observations=observations.pass_observations,
        warn_observations=observations.warn_observations,
        high_risk_observations=observations.high_risk_observations,
        returned_observations=observations.returned_observations,
    )
    return AdapterBridgeReportResult(
        report_version=ADAPTER_BRIDGE_REPORT_VERSION,
        bridge_version=ADAPTER_BRIDGE_VERSION,
        package_version=__version__,
        title="Memory Firewall Generic Adapter Report",
        generated_at=_utc_timestamp(),
        state_dir=str(output_dir),
        setup=setup,
        summary=summary,
        observations=observations,
        level_counts=_count_observation_fields(all_summaries, "level"),
        risk_category_counts=_count_observation_fields(
            all_summaries,
            "risk_categories",
        ),
        detector_counts=_count_observation_fields(
            all_summaries,
            "detector_names",
        ),
        next_steps=_adapter_report_next_steps(
            observations=observations,
            limit=limit,
        ),
        limitations=(
            "Local static generic adapter diagnostics report only.",
            "Observation rows are redacted handles; raw and proposed memory content are not included.",
            "Aggregate level, risk, and detector counts cover all loaded generic adapter observations; the recent rows table obeys the requested limit.",
            "The generic adapter bridge remains observe-only and does not suppress native memory writes.",
            "High-risk findings are deterministic integrity signals, not proof of objective truth or adversarial intent.",
            "The redacted share export removes local filesystem paths by default.",
        ),
    )


def _render_counter_list(items: Mapping[str, Any]) -> str:
    rows = []
    for key in sorted(items):
        value = items[key]
        rows.append(
            f"<li><span>{html.escape(str(key).replace('_', ' '))}</span>"
            f"<strong>{html.escape(str(value))}</strong></li>"
        )
    return "\n".join(rows)


def _render_adapter_report_rows(
    observations: tuple[AdapterBridgeObservationSummary, ...],
) -> str:
    rows = []
    for item in observations:
        rows.append(
            "<tr>"
            f"<td>{item.row_number}</td>"
            f"<td>{html.escape(item.recorded_bridge_version)}</td>"
            f"<td>{html.escape(item.recorded_at)}</td>"
            f"<td>{html.escape(item.level)}</td>"
            f"<td>{html.escape(item.highest_disposition)}</td>"
            f"<td>{html.escape(item.adapter_name)}</td>"
            f"<td>{html.escape(item.target_namespace)}</td>"
            f"<td>{item.finding_count}</td>"
            f"<td>{html.escape(', '.join(item.risk_categories) or 'none')}</td>"
            f"<td>{html.escape(', '.join(item.detector_names) or 'none')}</td>"
            f"<td>{html.escape(item.event_ref)}</td>"
            "</tr>"
        )
    if rows:
        return "".join(rows)
    return (
        "<tr><td colspan=\"11\">No local generic adapter observations found yet.</td></tr>"
    )


def render_adapter_report_html(report: AdapterBridgeReportResult) -> str:
    """Render a self-contained local HTML report over generic diagnostics."""

    limitations = "".join(
        f"<li>{html.escape(item)}</li>" for item in report.limitations
    )
    next_steps = "".join(
        f"<li>{html.escape(item)}</li>" for item in report.next_steps
    )
    if not next_steps:
        next_steps = "<li>No immediate next step.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(report.title)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #151515; background: #f7f7f4; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }}
    h1, h2 {{ line-height: 1.15; }}
    .lede {{ font-size: 1.05rem; max-width: 820px; color: #454545; }}
    .meta {{ color: #5b5b55; font-size: 0.92rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 12px; padding: 0; list-style: none; }}
    .grid li {{ background: white; border: 1px solid #deded8; border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 6px; }}
    .grid span {{ color: #5b5b55; font-size: 0.86rem; }}
    .grid strong {{ font-size: 1.3rem; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #deded8; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e8e8e2; text-align: left; vertical-align: top; }}
    th {{ background: #ecece5; font-size: 0.88rem; }}
    code {{ background: #ecece5; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
<main>
  <h1>{html.escape(report.title)}</h1>
  <p class="lede">This local report summarizes what the observe-only generic adapter bridge has seen in candidate memory writes. It uses redacted row handles and does not include raw candidate memory text.</p>
  <p class="meta">Generated at {html.escape(report.generated_at)}. Diagnostics: <code>{html.escape(report.state_dir)}</code>.</p>
  <h2>Setup</h2>
  <ul class="grid">
    {_render_counter_list(report.setup.to_dict())}
  </ul>
  <h2>Observation Summary</h2>
  <ul class="grid">
    {_render_counter_list(report.summary.to_dict())}
  </ul>
  <h2>All-History Level Counts</h2>
  <ul class="grid">
    {_render_counter_list(report.level_counts or {"none": 0})}
  </ul>
  <h2>All-History Risk Categories</h2>
  <ul class="grid">
    {_render_counter_list(report.risk_category_counts or {"none": 0})}
  </ul>
  <h2>Recent Redacted Observations</h2>
  <table>
    <thead><tr><th>Row</th><th>Version</th><th>Recorded</th><th>Level</th><th>Disposition</th><th>Adapter</th><th>Target</th><th>Findings</th><th>Risks</th><th>Detectors</th><th>Handle</th></tr></thead>
    <tbody>{_render_adapter_report_rows(report.observations.observations)}</tbody>
  </table>
  <h2>Next Steps</h2>
  <ul>{next_steps}</ul>
  <h2>Limitations</h2>
  <ul>{limitations}</ul>
</main>
</body>
</html>
"""


def write_adapter_report_bundle(
    report: AdapterBridgeReportResult,
    output_dir: str | Path,
) -> AdapterBridgeReportBundle:
    """Write a local generic adapter report JSON, HTML, and redacted export."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report_json_path = destination / ADAPTER_BRIDGE_REPORT_JSON_FILENAME
    html_path = destination / ADAPTER_BRIDGE_REPORT_HTML_FILENAME
    redacted_export_path = destination / ADAPTER_BRIDGE_REDACTED_EXPORT_FILENAME
    report_json_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    html_path.write_text(render_adapter_report_html(report), encoding="utf-8")
    redacted_export_path.write_text(
        json.dumps(report.to_redacted_share_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return AdapterBridgeReportBundle(
        report=report,
        output_dir=destination,
        report_json_path=report_json_path,
        html_path=html_path,
        redacted_export_path=redacted_export_path,
    )


def observe_memory_candidate(
    *,
    content: str,
    target_namespace: str = "memory",
    actor: str = "agent:local",
    user_or_tenant_scope: str = "local",
    source_type: SourceType = SourceType.UNKNOWN,
    source_id: str = "adapter-bridge",
    source_authority: SourceAuthority = SourceAuthority.UNTRUSTED,
    operation: MemoryOperation = MemoryOperation.CREATE,
    adapter_name: str = "local-adapter",
    state_dir: str | Path | None = None,
    metadata: Mapping[str, JSONScalar] | None = None,
) -> AdapterBridgeObserveResult:
    """Observe, scan, and persist one simple memory candidate."""

    output_dir = _resolve_state_dir(state_dir)
    event = memory_event_from_adapter_candidate(
        content=content,
        target_namespace=target_namespace,
        actor=actor,
        user_or_tenant_scope=user_or_tenant_scope,
        source_type=source_type,
        source_id=source_id,
        source_authority=source_authority,
        operation=operation,
        metadata=metadata,
    )
    observation = scan_adapter_candidate(event, adapter_name=adapter_name)
    append_adapter_observation(observation, state_dir=output_dir)
    row_number = len(load_adapter_observations(state_dir=output_dir))
    return AdapterBridgeObserveResult(
        bridge_version=ADAPTER_BRIDGE_VERSION,
        state_dir=str(output_dir),
        observation=_summary_from_row(observation.to_dict(), row_number=row_number),
    )
