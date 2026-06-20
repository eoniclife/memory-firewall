"""Hermes hook integration helpers.

This module intentionally does not import Hermes.  The public package owns the
event normalization, local scan, and diagnostic persistence.  Hermes-specific
loading lives in :mod:`memory_firewall.hermes_plugin`, which calls these helpers
from hook callbacks.
"""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .models import (
    JSONScalar,
    MemoryEvent,
    MemoryOperation,
    SourceAuthority,
    SourceType,
)
from .scan import ScanEventLevel, ScanEventResult, scan_event

HERMES_INTEGRATION_VERSION = "mf-11"
HERMES_EVENTS_FILENAME = "events.jsonl"
HERMES_OBSERVATIONS_FILENAME = "observations.jsonl"
HERMES_DIR_ENV = "MEMORY_FIREWALL_HERMES_DIR"
HERMES_SCAN_TURNS_ENV = "MEMORY_FIREWALL_HERMES_SCAN_TURNS"
HERMES_MODE_ENV = "MEMORY_FIREWALL_HERMES_MODE"
HERMES_DEFAULT_MODE = "observe"
HERMES_STATE_DIR_MODE = 0o700
HERMES_STATE_FILE_MODE = 0o600
_MAX_EVENT_TEXT_CHARS = 16_384
_MEMORY_TEXT_KEYS = (
    "content",
    "conclusion",
    "memory",
    "fact",
    "text",
    "body",
    "markdown",
    "description",
    "entry",
)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def hermes_turn_scan_enabled() -> bool:
    """Return whether the Hermes plugin should scan every completed turn."""

    return _truthy_env(HERMES_SCAN_TURNS_ENV)


def hermes_mode() -> str:
    """Return the configured Hermes integration mode.

    MF-11 only implements observe mode.  Unknown values are normalized to
    observe so a typo cannot unexpectedly block an agent's tools.
    """

    value = os.environ.get(HERMES_MODE_ENV, HERMES_DEFAULT_MODE).strip().lower()
    if value not in {HERMES_DEFAULT_MODE}:
        return HERMES_DEFAULT_MODE
    return value


def _truncate_text(value: str) -> str:
    if len(value) <= _MAX_EVENT_TEXT_CHARS:
        return value
    return value[: _MAX_EVENT_TEXT_CHARS - 24] + "\n[truncated by Memory Firewall]"


def _string_or_empty(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return str(value)


def _scalar_metadata(value: Any) -> JSONScalar:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    return _string_or_empty(value)


def _base_metadata(
    *,
    hook_name: str,
    tool_name: str,
    session_id: str,
    tool_call_id: str,
    turn_id: str,
) -> dict[str, JSONScalar]:
    metadata: dict[str, JSONScalar] = {
        "integration": "hermes",
        "integration_version": HERMES_INTEGRATION_VERSION,
        "hook_name": hook_name,
        "tool_name": tool_name,
    }
    if session_id:
        metadata["session_id"] = session_id
    if tool_call_id:
        metadata["tool_call_id"] = tool_call_id
    if turn_id:
        metadata["turn_id"] = turn_id
    return metadata


def _source_id(
    *,
    tool_name: str,
    session_id: str,
    tool_call_id: str,
    turn_id: str,
    suffix: str,
) -> str:
    parts = ["hermes", tool_name or "unknown"]
    if session_id:
        parts.append(session_id)
    if turn_id:
        parts.append(turn_id)
    if tool_call_id:
        parts.append(tool_call_id)
    if suffix:
        parts.append(suffix)
    return ":".join(parts)


def _operation_from_action(action: str) -> MemoryOperation:
    normalized = action.strip().lower()
    if normalized == "add":
        return MemoryOperation.CREATE
    if normalized == "replace":
        return MemoryOperation.UPDATE
    if normalized == "remove":
        return MemoryOperation.DELETE
    return MemoryOperation.UPSERT


def _event_from_payload(
    *,
    timestamp: str,
    actor: str,
    user_or_tenant_scope: str,
    source_type: SourceType,
    source_id: str,
    source_authority: SourceAuthority,
    raw_or_redacted_content: str,
    proposed_memory: str,
    operation: MemoryOperation,
    target_namespace: str,
    metadata: Mapping[str, JSONScalar],
) -> MemoryEvent:
    return MemoryEvent.from_adapter_payload(
        {
            "timestamp": timestamp,
            "actor": actor,
            "user_or_tenant_scope": user_or_tenant_scope,
            "source_type": source_type.value,
            "source_id": source_id,
            "source_authority": source_authority.value,
            "raw_or_redacted_content": _truncate_text(raw_or_redacted_content),
            "proposed_memory": _truncate_text(proposed_memory),
            "operation": operation.value,
            "target_namespace": target_namespace,
            "metadata": dict(metadata),
        }
    )


def _memory_tool_events(
    args: Mapping[str, Any],
    *,
    timestamp: str,
    session_id: str,
    tool_call_id: str,
    turn_id: str,
    hook_name: str,
) -> tuple[MemoryEvent, ...]:
    raw_ops = args.get("operations")
    operations: list[Mapping[str, Any]]
    if isinstance(raw_ops, list):
        operations = [item for item in raw_ops if isinstance(item, Mapping)]
    else:
        operations = [args]

    target = _string_or_empty(args.get("target") or "memory") or "memory"
    events: list[MemoryEvent] = []
    for index, operation_payload in enumerate(operations, start=1):
        action = _string_or_empty(operation_payload.get("action") or args.get("action"))
        content = _string_or_empty(
            operation_payload.get("content")
            or operation_payload.get("old_text")
            or args.get("content")
            or args.get("old_text")
        )
        if not action and not content:
            continue
        metadata = _base_metadata(
            hook_name=hook_name,
            tool_name="memory",
            session_id=session_id,
            tool_call_id=tool_call_id,
            turn_id=turn_id,
        )
        metadata["target"] = target
        metadata["action"] = action or "unknown"
        metadata["operation_index"] = index
        events.append(
            _event_from_payload(
                timestamp=timestamp,
                actor="hermes:agent",
                user_or_tenant_scope=session_id or "hermes:local",
                source_type=SourceType.AGENT_OUTPUT,
                source_id=_source_id(
                    tool_name="memory",
                    session_id=session_id,
                    tool_call_id=tool_call_id,
                    turn_id=turn_id,
                    suffix=f"{target}:{index}",
                ),
                source_authority=SourceAuthority.UNTRUSTED,
                raw_or_redacted_content=content,
                proposed_memory=content,
                operation=_operation_from_action(action),
                target_namespace=f"hermes:memory:{target}",
                metadata=metadata,
            )
        )
    return tuple(events)


def _first_memory_text(args: Mapping[str, Any]) -> tuple[str, str] | None:
    for key in _MEMORY_TEXT_KEYS:
        text = _string_or_empty(args.get(key)).strip()
        if text:
            return key, text
    return None


def _looks_like_memory_write_tool(tool_name: str, args: Mapping[str, Any]) -> bool:
    if not args:
        return False
    lowered = tool_name.strip().lower()
    if lowered in {"mem0_conclude", "honcho_conclude"}:
        return True
    if lowered.endswith("_conclude") or lowered.endswith("_remember"):
        return _first_memory_text(args) is not None
    if "memory" in lowered and _first_memory_text(args) is not None:
        return True
    if "remember" in lowered and _first_memory_text(args) is not None:
        return True
    if "gbrain" in lowered and any(
        token in lowered
        for token in ("put_page", "capture", "timeline", "write", "sync")
    ):
        return _first_memory_text(args) is not None
    return False


def memory_events_from_hermes_tool_call(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    timestamp: str | None = None,
    session_id: str = "",
    tool_call_id: str = "",
    turn_id: str = "",
    hook_name: str = "post_tool_call",
) -> tuple[MemoryEvent, ...]:
    """Normalize high-signal Hermes memory tool calls into MemoryEvents."""

    if not isinstance(args, Mapping):
        return ()
    recorded_at = timestamp or _utc_timestamp()
    normalized_tool = tool_name.strip()
    if normalized_tool == "memory":
        return _memory_tool_events(
            args,
            timestamp=recorded_at,
            session_id=session_id,
            tool_call_id=tool_call_id,
            turn_id=turn_id,
            hook_name=hook_name,
        )
    if not _looks_like_memory_write_tool(normalized_tool, args):
        return ()
    text_pair = _first_memory_text(args)
    if text_pair is None:
        return ()
    text_key, text = text_pair
    metadata = _base_metadata(
        hook_name=hook_name,
        tool_name=normalized_tool,
        session_id=session_id,
        tool_call_id=tool_call_id,
        turn_id=turn_id,
    )
    metadata["source_arg"] = text_key
    for key in ("peer", "target", "namespace", "user_id"):
        if key in args:
            metadata[key] = _scalar_metadata(args[key])
    target_suffix = _string_or_empty(args.get("peer") or args.get("target")).strip()
    target_namespace = f"hermes:provider-tool:{normalized_tool}"
    if target_suffix:
        target_namespace = f"{target_namespace}:{target_suffix}"
    return (
        _event_from_payload(
            timestamp=recorded_at,
            actor="hermes:agent",
            user_or_tenant_scope=session_id or "hermes:local",
            source_type=SourceType.AGENT_OUTPUT,
            source_id=_source_id(
                tool_name=normalized_tool,
                session_id=session_id,
                tool_call_id=tool_call_id,
                turn_id=turn_id,
                suffix=text_key,
            ),
            source_authority=SourceAuthority.UNTRUSTED,
            raw_or_redacted_content=text,
            proposed_memory=text,
            operation=MemoryOperation.CREATE,
            target_namespace=target_namespace,
            metadata=metadata,
        ),
    )


def memory_event_from_hermes_turn(
    *,
    user_message: str,
    assistant_response: str,
    timestamp: str | None = None,
    session_id: str = "",
    turn_id: str = "",
    model: str = "",
    platform: str = "",
) -> MemoryEvent | None:
    """Build an opt-in turn-level event for implicit memory providers."""

    user_text = _string_or_empty(user_message).strip()
    assistant_text = _string_or_empty(assistant_response).strip()
    if not user_text and not assistant_text:
        return None
    metadata = _base_metadata(
        hook_name="post_llm_call",
        tool_name="implicit_turn",
        session_id=session_id,
        tool_call_id="",
        turn_id=turn_id,
    )
    if model:
        metadata["model"] = model
    if platform:
        metadata["platform"] = platform
    raw_content = "\n\n".join(
        part for part in (f"user: {user_text}", f"assistant: {assistant_text}") if part
    )
    return _event_from_payload(
        timestamp=timestamp or _utc_timestamp(),
        actor="hermes:agent",
        user_or_tenant_scope=session_id or "hermes:local",
        source_type=SourceType.AGENT_OUTPUT,
        source_id=_source_id(
            tool_name="implicit_turn",
            session_id=session_id,
            tool_call_id="",
            turn_id=turn_id,
            suffix=model or "model",
        ),
        source_authority=SourceAuthority.UNTRUSTED,
        raw_or_redacted_content=raw_content,
        proposed_memory=assistant_text,
        operation=MemoryOperation.UPSERT,
        target_namespace="hermes:implicit-turn",
        metadata=metadata,
    )


@dataclass(frozen=True, slots=True)
class HermesObservation:
    """One local observation written by the Hermes hook alpha."""

    integration_version: str
    recorded_at: str
    hook_name: str
    tool_name: str
    mode: str
    blocked_by_firewall: bool
    event: MemoryEvent
    scan: ScanEventResult

    def __post_init__(self) -> None:
        if self.integration_version != HERMES_INTEGRATION_VERSION:
            raise ValueError(
                f"integration_version must be {HERMES_INTEGRATION_VERSION}"
            )
        if not self.recorded_at:
            raise ValueError("recorded_at must not be empty")
        if not self.hook_name:
            raise ValueError("hook_name must not be empty")
        if not self.tool_name:
            raise ValueError("tool_name must not be empty")
        if self.mode != HERMES_DEFAULT_MODE:
            raise ValueError(f"mode must be {HERMES_DEFAULT_MODE}")
        if not isinstance(self.blocked_by_firewall, bool):
            raise TypeError("blocked_by_firewall must be bool")
        if not isinstance(self.event, MemoryEvent):
            raise TypeError("event must be a MemoryEvent")
        if not isinstance(self.scan, ScanEventResult):
            raise TypeError("scan must be a ScanEventResult")
        if self.scan.event_id != self.event.event_id:
            raise ValueError("scan event_id must match event event_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_version": self.integration_version,
            "recorded_at": self.recorded_at,
            "hook_name": self.hook_name,
            "tool_name": self.tool_name,
            "mode": self.mode,
            "blocked_by_firewall": self.blocked_by_firewall,
            "event": self.event.to_dict(),
            "scan": self.scan.to_dict(),
        }


def scan_hermes_event(
    event: MemoryEvent,
    *,
    hook_name: str,
    tool_name: str,
    recorded_at: str | None = None,
) -> HermesObservation:
    """Scan one Hermes-derived MemoryEvent and wrap the local observation."""

    return HermesObservation(
        integration_version=HERMES_INTEGRATION_VERSION,
        recorded_at=recorded_at or _utc_timestamp(),
        hook_name=hook_name,
        tool_name=tool_name or "unknown",
        mode=hermes_mode(),
        blocked_by_firewall=False,
        event=event,
        scan=scan_event(event),
    )


def default_hermes_state_dir(hermes_home: str | Path | None = None) -> Path:
    """Return the local diagnostics directory for Hermes integration state."""

    override = os.environ.get(HERMES_DIR_ENV)
    if override:
        return Path(override).expanduser()
    if hermes_home is not None:
        return Path(hermes_home).expanduser() / "memory-firewall"
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        return Path(env_home).expanduser() / "memory-firewall"
    return Path.home() / ".hermes" / "memory-firewall"


def _resolve_hermes_state_dir(state_dir: str | Path | None = None) -> Path:
    if state_dir is not None:
        return Path(state_dir).expanduser()
    return default_hermes_state_dir()


def _ensure_private_hermes_state_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True, mode=HERMES_STATE_DIR_MODE)
    current_mode = stat.S_IMODE(output_dir.stat().st_mode)
    if current_mode != HERMES_STATE_DIR_MODE:
        output_dir.chmod(HERMES_STATE_DIR_MODE)


def _append_private_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if isinstance(nofollow, int):
        flags |= nofollow
    fd = os.open(path, flags, HERMES_STATE_FILE_MODE)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != HERMES_STATE_FILE_MODE:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, HERMES_STATE_FILE_MODE)
            else:
                path.chmod(HERMES_STATE_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    finally:
        if fd >= 0:
            os.close(fd)


def append_hermes_observation(
    observation: HermesObservation,
    *,
    state_dir: str | Path | None = None,
) -> None:
    """Append one local Hermes observation and its normalized event."""

    output_dir = _resolve_hermes_state_dir(state_dir)
    _ensure_private_hermes_state_dir(output_dir)
    _append_private_jsonl(
        output_dir / HERMES_EVENTS_FILENAME, observation.event.to_dict()
    )
    _append_private_jsonl(
        output_dir / HERMES_OBSERVATIONS_FILENAME, observation.to_dict()
    )


def record_hermes_events(
    events: tuple[MemoryEvent, ...],
    *,
    hook_name: str,
    tool_name: str,
    state_dir: str | Path | None = None,
) -> tuple[HermesObservation, ...]:
    """Scan and persist normalized Hermes events."""

    observations = tuple(
        scan_hermes_event(event, hook_name=hook_name, tool_name=tool_name)
        for event in events
    )
    for observation in observations:
        append_hermes_observation(observation, state_dir=state_dir)
    return observations


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


@dataclass(frozen=True, slots=True)
class HermesStatus:
    """Compact readout over local Hermes Memory Firewall observations."""

    integration_version: str
    state_dir: str
    total_observations: int
    high_risk_observations: int
    warn_observations: int
    pass_observations: int
    blocked_by_firewall: int
    latest_recorded_at: str | None

    def __post_init__(self) -> None:
        if self.integration_version != HERMES_INTEGRATION_VERSION:
            raise ValueError(
                f"integration_version must be {HERMES_INTEGRATION_VERSION}"
            )
        if not self.state_dir:
            raise ValueError("state_dir must not be empty")
        for field_name in (
            "total_observations",
            "high_risk_observations",
            "warn_observations",
            "pass_observations",
            "blocked_by_firewall",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_version": self.integration_version,
            "state_dir": self.state_dir,
            "total_observations": self.total_observations,
            "high_risk_observations": self.high_risk_observations,
            "warn_observations": self.warn_observations,
            "pass_observations": self.pass_observations,
            "blocked_by_firewall": self.blocked_by_firewall,
            "latest_recorded_at": self.latest_recorded_at,
            "mode": HERMES_DEFAULT_MODE,
            "observe_only": True,
            "production_enforcement": False,
        }


def load_hermes_observations(
    *,
    state_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load raw local Hermes observation rows."""

    output_dir = _resolve_hermes_state_dir(state_dir)
    return _load_jsonl(output_dir / HERMES_OBSERVATIONS_FILENAME)


def summarize_hermes_observations(
    *,
    state_dir: str | Path | None = None,
) -> HermesStatus:
    """Return a compact status object over local Hermes observations."""

    output_dir = _resolve_hermes_state_dir(state_dir)
    rows = load_hermes_observations(state_dir=output_dir)
    high_risk = 0
    warn = 0
    passed = 0
    blocked = 0
    latest: str | None = None
    for row in rows:
        if row.get("blocked_by_firewall") is True:
            blocked += 1
        recorded_at = row.get("recorded_at")
        if isinstance(recorded_at, str) and (latest is None or recorded_at > latest):
            latest = recorded_at
        scan = row.get("scan")
        level = scan.get("level") if isinstance(scan, dict) else None
        if level == ScanEventLevel.HIGH_RISK.value:
            high_risk += 1
        elif level == ScanEventLevel.WARN.value:
            warn += 1
        elif level == ScanEventLevel.PASS.value:
            passed += 1
    return HermesStatus(
        integration_version=HERMES_INTEGRATION_VERSION,
        state_dir=str(output_dir),
        total_observations=len(rows),
        high_risk_observations=high_risk,
        warn_observations=warn,
        pass_observations=passed,
        blocked_by_firewall=blocked,
        latest_recorded_at=latest,
    )
