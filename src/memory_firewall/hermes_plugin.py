"""Hermes plugin entry point for Memory Firewall.

Hermes loads this module through the ``hermes_agent.plugins`` entry point when
the user enables ``memory-firewall`` in ``plugins.enabled``.  All hook handlers
are fail-open: diagnostics must never break the host agent.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from .hermes import (
    hermes_turn_scan_enabled,
    memory_event_from_hermes_turn,
    memory_events_from_hermes_tool_call,
    record_hermes_events,
)

logger = logging.getLogger(__name__)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def on_pre_tool_call(**_kwargs: Any) -> None:
    """Observe the pre-tool seam without blocking in MF-11."""

    return None


def on_post_tool_call(**kwargs: Any) -> None:
    """Record high-signal Hermes memory write attempts after tool execution."""

    try:
        tool_name = _str(kwargs.get("tool_name"))
        events = memory_events_from_hermes_tool_call(
            tool_name,
            _mapping(kwargs.get("args")),
            session_id=_str(kwargs.get("session_id")),
            tool_call_id=_str(kwargs.get("tool_call_id")),
            turn_id=_str(kwargs.get("turn_id")),
            hook_name="post_tool_call",
        )
        if events:
            record_hermes_events(
                events,
                hook_name="post_tool_call",
                tool_name=tool_name or "unknown",
            )
    except Exception as exc:  # pragma: no cover - fail-open host boundary
        logger.debug("Memory Firewall Hermes post_tool_call failed: %s", exc)


def on_post_llm_call(**kwargs: Any) -> None:
    """Optionally record turn-level candidates for implicit memory providers."""

    if not hermes_turn_scan_enabled():
        return None
    try:
        event = memory_event_from_hermes_turn(
            user_message=_str(kwargs.get("user_message")),
            assistant_response=_str(kwargs.get("assistant_response")),
            session_id=_str(kwargs.get("session_id")),
            turn_id=_str(kwargs.get("turn_id")),
            model=_str(kwargs.get("model")),
            platform=_str(kwargs.get("platform")),
        )
        if event is not None:
            record_hermes_events(
                (event,),
                hook_name="post_llm_call",
                tool_name="implicit_turn",
            )
    except Exception as exc:  # pragma: no cover - fail-open host boundary
        logger.debug("Memory Firewall Hermes post_llm_call failed: %s", exc)
    return None


def register(ctx: Any) -> None:
    """Register Memory Firewall Hermes hook callbacks."""

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("post_llm_call", on_post_llm_call)
