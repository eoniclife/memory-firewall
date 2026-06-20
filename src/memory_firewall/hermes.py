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
    RecommendedDisposition,
    RiskCategory,
    SourceAuthority,
    SourceType,
)
from .scan import ScanEventLevel, ScanEventResult, scan_event
from .version import __version__

HERMES_INTEGRATION_VERSION = "mf-13"
HERMES_EVENTS_FILENAME = "events.jsonl"
HERMES_OBSERVATIONS_FILENAME = "observations.jsonl"
HERMES_PLUGIN_NAME = "memory-firewall"
HERMES_PLUGIN_MANIFEST_FILENAME = "plugin.yaml"
HERMES_PLUGIN_INIT_FILENAME = "__init__.py"
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
_SAFE_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._-"
)
_SAFE_MEMORY_TARGETS = frozenset(
    (
        "default",
        "global",
        "memory",
        "memories",
        "profile",
        "project",
        "semantic",
        "session",
        "system",
        "user",
    )
)
_MEMORY_OPERATIONS = frozenset(item.value for item in MemoryOperation)
_SOURCE_AUTHORITIES = frozenset(item.value for item in SourceAuthority)
_SCAN_LEVELS = frozenset(item.value for item in ScanEventLevel)
_RECOMMENDED_DISPOSITIONS = frozenset(item.value for item in RecommendedDisposition)
_RISK_CATEGORIES = frozenset(item.value for item in RiskCategory)


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


@dataclass(frozen=True, slots=True)
class HermesObservationSummary:
    """Redacted row for inspecting a stored Hermes observation."""

    integration_version: str
    row_number: int
    recorded_at: str
    hook_name: str
    tool_name: str
    mode: str
    blocked_by_firewall: bool
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
        if self.integration_version != HERMES_INTEGRATION_VERSION:
            raise ValueError(
                f"integration_version must be {HERMES_INTEGRATION_VERSION}"
            )
        if self.row_number < 1:
            raise ValueError("row_number must be positive")
        for field_name in (
            "recorded_at",
            "hook_name",
            "tool_name",
            "mode",
            "event_ref",
            "operation",
            "source_authority",
            "target_namespace",
            "level",
            "highest_disposition",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must not be empty")
        if self.mode != HERMES_DEFAULT_MODE:
            raise ValueError(f"mode must be {HERMES_DEFAULT_MODE}")
        if not isinstance(self.blocked_by_firewall, bool):
            raise TypeError("blocked_by_firewall must be bool")
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
            "integration_version": self.integration_version,
            "row_number": self.row_number,
            "recorded_at": self.recorded_at,
            "hook_name": self.hook_name,
            "tool_name": self.tool_name,
            "mode": self.mode,
            "blocked_by_firewall": self.blocked_by_firewall,
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
class HermesObservationList:
    """Recent redacted rows over local Hermes observations."""

    integration_version: str
    state_dir: str
    limit: int
    total_observations: int
    returned_observations: int
    observations: tuple[HermesObservationSummary, ...]

    def __post_init__(self) -> None:
        if self.integration_version != HERMES_INTEGRATION_VERSION:
            raise ValueError(
                f"integration_version must be {HERMES_INTEGRATION_VERSION}"
            )
        if not self.state_dir:
            raise ValueError("state_dir must not be empty")
        if self.limit < 1:
            raise ValueError("limit must be positive")
        for field_name in ("total_observations", "returned_observations"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.returned_observations != len(self.observations):
            raise ValueError("returned_observations must equal observations length")
        if self.returned_observations > self.total_observations:
            raise ValueError("returned_observations cannot exceed total_observations")

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_version": self.integration_version,
            "state_dir": self.state_dir,
            "limit": self.limit,
            "total_observations": self.total_observations,
            "returned_observations": self.returned_observations,
            "observations": [item.to_dict() for item in self.observations],
            "mode": HERMES_DEFAULT_MODE,
            "observe_only": True,
            "production_enforcement": False,
            "raw_content_included": False,
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


def default_hermes_home() -> Path:
    """Return the Hermes home directory used for user plugin shims."""

    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".hermes"


def default_hermes_plugin_dir(hermes_home: str | Path | None = None) -> Path:
    """Return the user-plugin shim directory Hermes' current CLI can discover."""

    home = (
        Path(hermes_home).expanduser()
        if hermes_home is not None
        else default_hermes_home()
    )
    return home / "plugins" / HERMES_PLUGIN_NAME


def hermes_plugin_manifest_text() -> str:
    """Return the directory-plugin manifest for the Hermes compatibility shim."""

    return (
        "manifest_version: 1\n"
        f"name: {HERMES_PLUGIN_NAME}\n"
        f"version: {__version__}\n"
        'description: "Memory Firewall observe-only hook alpha for memory-write diagnostics."\n'
        "kind: standalone\n"
        "provides_hooks:\n"
        "  - pre_tool_call\n"
        "  - post_tool_call\n"
        "  - post_llm_call\n"
    )


def hermes_plugin_init_text() -> str:
    """Return the directory-plugin shim that delegates to the installed package."""

    return (
        '"""Hermes user-plugin shim generated by Memory Firewall."""\n\n'
        "from memory_firewall.hermes_plugin import register\n\n"
        '__all__ = ["register"]\n'
    )


@dataclass(frozen=True, slots=True)
class HermesPluginInstallResult:
    """Result of installing the Hermes user-plugin compatibility shim."""

    integration_version: str
    plugin_name: str
    hermes_home: str
    plugin_dir: str
    manifest_path: str
    init_path: str
    created: bool
    updated: bool
    enable_command: str
    observe_only: bool = True
    production_enforcement: bool = False

    def __post_init__(self) -> None:
        if self.integration_version != HERMES_INTEGRATION_VERSION:
            raise ValueError(
                f"integration_version must be {HERMES_INTEGRATION_VERSION}"
            )
        if self.plugin_name != HERMES_PLUGIN_NAME:
            raise ValueError(f"plugin_name must be {HERMES_PLUGIN_NAME}")
        for field_name in (
            "hermes_home",
            "plugin_dir",
            "manifest_path",
            "init_path",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_version": self.integration_version,
            "plugin_name": self.plugin_name,
            "hermes_home": self.hermes_home,
            "plugin_dir": self.plugin_dir,
            "manifest_path": self.manifest_path,
            "init_path": self.init_path,
            "created": self.created,
            "updated": self.updated,
            "enable_command": self.enable_command,
            "observe_only": self.observe_only,
            "production_enforcement": self.production_enforcement,
        }


def install_hermes_plugin_shim(
    *,
    hermes_home: str | Path | None = None,
    force: bool = False,
) -> HermesPluginInstallResult:
    """Install the user-plugin shim Hermes' current CLI can list and enable.

    Hermes v0.16.0 runtime plugin loading supports ``hermes_agent.plugins`` entry
    points, but the ``hermes plugins enable`` helper discovers only bundled/user
    plugin directories.  This shim gives that CLI a normal user plugin directory
    while keeping all runtime logic in the installed ``memory_firewall`` package.
    """

    home = (
        Path(hermes_home).expanduser()
        if hermes_home is not None
        else default_hermes_home()
    )
    plugin_dir = default_hermes_plugin_dir(home)
    manifest_path = plugin_dir / HERMES_PLUGIN_MANIFEST_FILENAME
    init_path = plugin_dir / HERMES_PLUGIN_INIT_FILENAME
    manifest_text = hermes_plugin_manifest_text()
    init_text = hermes_plugin_init_text()
    existed = plugin_dir.exists()
    created = not existed
    updated = False

    if existed and not plugin_dir.is_dir():
        raise FileExistsError(
            f"Hermes plugin path exists but is not a directory: {plugin_dir}"
        )

    plugin_dir.mkdir(parents=True, exist_ok=True)
    for path, text in ((manifest_path, manifest_text), (init_path, init_text)):
        if path.exists() and not path.is_file():
            raise FileExistsError(
                f"Hermes plugin shim path exists but is not a file: {path}"
            )
        existing_text = path.read_text(encoding="utf-8") if path.exists() else None
        if existing_text == text:
            continue
        if existing_text is not None and not force:
            raise FileExistsError(
                f"Hermes plugin shim file already exists with different content: {path}. "
                "Run with force=True or --force to overwrite."
            )
        path.write_text(text, encoding="utf-8")
        updated = True

    return HermesPluginInstallResult(
        integration_version=HERMES_INTEGRATION_VERSION,
        plugin_name=HERMES_PLUGIN_NAME,
        hermes_home=str(home),
        plugin_dir=str(plugin_dir),
        manifest_path=str(manifest_path),
        init_path=str(init_path),
        created=created,
        updated=updated,
        enable_command=f"hermes plugins enable {HERMES_PLUGIN_NAME}",
    )


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
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                rows.append(
                    _diagnostic_observation_row(
                        path=path,
                        line_number=line_number,
                        reason="invalid-json",
                    )
                )
                continue
            if isinstance(payload, dict):
                rows.append(payload)
            else:
                rows.append(
                    _diagnostic_observation_row(
                        path=path,
                        line_number=line_number,
                        reason="non-object-json",
                    )
                )
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


def _string_from_mapping(
    value: Mapping[str, Any],
    key: str,
    *,
    default: str,
) -> str:
    raw = value.get(key)
    if isinstance(raw, str) and raw:
        return raw
    return default


def _safe_token(value: Any, *, default: str, max_chars: int = 96) -> str:
    if not isinstance(value, str) or not value:
        return default
    if len(value) > max_chars:
        return default
    if all(char in _SAFE_TOKEN_CHARS for char in value):
        return value
    return default


def _enum_value(value: Any, *, allowed: frozenset[str], default: str) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    return default


def _summary_mode(value: Any) -> str:
    if value == HERMES_DEFAULT_MODE:
        return HERMES_DEFAULT_MODE
    return HERMES_DEFAULT_MODE


def _safe_recorded_at(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "unavailable-recorded-at"
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return "unavailable-recorded-at"
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return "unavailable-recorded-at"
    return value


def _redacted_target_namespace(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "redacted-target"
    parts = value.split(":")
    if parts[:2] == ["hermes", "memory"]:
        target = parts[2] if len(parts) > 2 else "memory"
        safe_target = target if target in _SAFE_MEMORY_TARGETS else "redacted"
        return f"hermes:memory:{safe_target}"
    if parts[:2] == ["hermes", "provider-tool"]:
        tool = _safe_token(parts[2] if len(parts) > 2 else "", default="unknown-tool")
        if len(parts) > 3:
            return f"hermes:provider-tool:{tool}:redacted"
        return f"hermes:provider-tool:{tool}"
    if value == "hermes:implicit-turn":
        return value
    if value == "hermes:diagnostics:observations":
        return value
    return "redacted-target"


def _diagnostic_observation_row(
    *,
    path: Path,
    line_number: int,
    reason: str,
) -> dict[str, Any]:
    safe_reason = _safe_token(reason, default="malformed-row")
    return {
        "recorded_at": "unavailable-recorded-at",
        "hook_name": "diagnostic",
        "tool_name": _safe_token(path.name, default="diagnostics"),
        "mode": HERMES_DEFAULT_MODE,
        "blocked_by_firewall": False,
        "event": {
            "event_id": "unavailable-event",
            "operation": MemoryOperation.UPSERT.value,
            "source_authority": SourceAuthority.UNTRUSTED.value,
            "target_namespace": "hermes:diagnostics:observations",
        },
        "scan": {
            "level": ScanEventLevel.WARN.value,
            "highest_disposition": RecommendedDisposition.REVIEW.value,
            "finding_count": 0,
            "contradiction_count": 0,
            "detector_result": {
                "findings": [
                    {
                        "risk_category": RiskCategory.PROVENANCE_GAP.value,
                        "detector_name": f"diagnostic-{safe_reason}",
                    }
                ],
            },
        },
    }


def _non_negative_int_from_mapping(value: Mapping[str, Any], key: str) -> int | None:
    raw = value.get(key)
    if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
        return raw
    return None


def _tuple_field_from_findings(
    findings: list[Any],
    key: str,
) -> tuple[str, ...]:
    values: set[str] = set()
    for item in findings:
        if not isinstance(item, Mapping):
            continue
        raw = item.get(key)
        if not isinstance(raw, str) or not raw:
            continue
        if key == "risk_category":
            if raw in _RISK_CATEGORIES:
                values.add(raw)
        elif key == "detector_name":
            values.add(_safe_token(raw, default="redacted-detector"))
        else:
            values.add(_safe_token(raw, default="redacted-value"))
    return tuple(sorted(values))


def _hermes_observation_summary_from_row(
    row: Mapping[str, Any],
    *,
    row_number: int,
) -> HermesObservationSummary:
    event = row.get("event")
    event_payload = event if isinstance(event, Mapping) else {}
    scan = row.get("scan")
    scan_payload = scan if isinstance(scan, Mapping) else {}
    detector_result = scan_payload.get("detector_result")
    detector_payload = detector_result if isinstance(detector_result, Mapping) else {}
    raw_findings = detector_payload.get("findings")
    findings = raw_findings if isinstance(raw_findings, list) else []
    finding_count = _non_negative_int_from_mapping(scan_payload, "finding_count")
    if finding_count is None:
        finding_count = sum(1 for item in findings if isinstance(item, Mapping))
    contradiction_count = _non_negative_int_from_mapping(
        scan_payload,
        "contradiction_count",
    )
    if contradiction_count is None:
        contradiction_count = 0
    blocked = row.get("blocked_by_firewall")
    return HermesObservationSummary(
        integration_version=HERMES_INTEGRATION_VERSION,
        row_number=row_number,
        recorded_at=_safe_recorded_at(row.get("recorded_at")),
        hook_name=_safe_token(row.get("hook_name"), default="unknown-hook"),
        tool_name=_safe_token(row.get("tool_name"), default="unknown-tool"),
        mode=_summary_mode(row.get("mode")),
        blocked_by_firewall=blocked if isinstance(blocked, bool) else False,
        event_ref=f"observation-row-{row_number}",
        operation=_enum_value(
            event_payload.get("operation"),
            allowed=_MEMORY_OPERATIONS,
            default=MemoryOperation.UPSERT.value,
        ),
        source_authority=_enum_value(
            event_payload.get("source_authority"),
            allowed=_SOURCE_AUTHORITIES,
            default=SourceAuthority.UNTRUSTED.value,
        ),
        target_namespace=_redacted_target_namespace(
            event_payload.get("target_namespace")
        ),
        level=_enum_value(
            scan_payload.get("level"),
            allowed=_SCAN_LEVELS,
            default=ScanEventLevel.WARN.value,
        ),
        highest_disposition=_enum_value(
            scan_payload.get("highest_disposition"),
            allowed=_RECOMMENDED_DISPOSITIONS,
            default=RecommendedDisposition.REVIEW.value,
        ),
        finding_count=finding_count,
        contradiction_count=contradiction_count,
        risk_categories=_tuple_field_from_findings(findings, "risk_category"),
        detector_names=_tuple_field_from_findings(findings, "detector_name"),
    )


def recent_hermes_observations(
    *,
    state_dir: str | Path | None = None,
    limit: int = 20,
) -> HermesObservationList:
    """Return newest-first redacted summaries over local Hermes observations."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    output_dir = _resolve_hermes_state_dir(state_dir)
    rows = load_hermes_observations(state_dir=output_dir)
    summaries = tuple(
        _hermes_observation_summary_from_row(row, row_number=index)
        for index, row in enumerate(rows, start=1)
    )
    recent = tuple(reversed(summaries[-limit:]))
    return HermesObservationList(
        integration_version=HERMES_INTEGRATION_VERSION,
        state_dir=str(output_dir),
        limit=limit,
        total_observations=len(rows),
        returned_observations=len(recent),
        observations=recent,
    )


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
        recorded_at = _safe_recorded_at(row.get("recorded_at"))
        if recorded_at != "unavailable-recorded-at" and (
            latest is None or recorded_at > latest
        ):
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
