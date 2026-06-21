"""Generic local adapter bridge for one memory candidate at a time."""

from __future__ import annotations

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

ADAPTER_BRIDGE_VERSION = "mf-21"
ADAPTER_BRIDGE_DIR_ENV = "MEMORY_FIREWALL_ADAPTER_DIR"
ADAPTER_BRIDGE_EVENTS_FILENAME = "events.jsonl"
ADAPTER_BRIDGE_OBSERVATIONS_FILENAME = "observations.jsonl"
ADAPTER_BRIDGE_STATE_DIR_MODE = 0o700
ADAPTER_BRIDGE_STATE_FILE_MODE = 0o600
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_RFC3339_TIMESTAMP_RE = re.compile(RFC3339_TIMESTAMP_PATTERN)
_RISK_CATEGORIES = frozenset(item.value for item in RiskCategory)
_PUBLIC_DETECTOR_NAMES = frozenset(
    definition.name for definition in default_detector_pack().definitions
)


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
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _safe_target_namespace(value: object) -> str:
    if isinstance(value, str) and _SAFE_TARGET_RE.fullmatch(value):
        return value
    return "redacted-target"


def _safe_token(value: object, *, default: str) -> str:
    if isinstance(value, str) and _SAFE_TARGET_RE.fullmatch(value):
        return value
    return default


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
            if raw in _PUBLIC_DETECTOR_NAMES:
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
        recorded_bridge_version=_safe_token(
            row.get("bridge_version"),
            default="unknown-version",
        ),
        row_number=row_number,
        recorded_at=_safe_recorded_at(row.get("recorded_at")),
        adapter_name=_safe_token(row.get("adapter_name"), default="unknown-adapter"),
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
