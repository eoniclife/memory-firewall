"""SQLite-backed reference memory store for local proxy demos."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analysis import MemoryStateAssertion
from .models import MemoryEvent, SourceAuthority, _coerce_enum, _require_string

REFERENCE_CHANNEL_NATIVE = "native"
REFERENCE_CHANNEL_GOVERNED = "governed_context_preview"


def _memory_key_from_event(event: MemoryEvent) -> str:
    subject = event.metadata.get("state_subject")
    predicate = event.metadata.get("state_predicate")
    if not isinstance(subject, str) or not subject:
        subject = f"{event.user_or_tenant_scope}:{event.target_namespace}"
    if not isinstance(predicate, str) or not predicate:
        predicate = "proposed_memory"
    return f"{subject}::{predicate}"


def _memory_value_from_event(event: MemoryEvent) -> str:
    value = event.metadata.get("state_object")
    if isinstance(value, str) and value:
        return value
    return event.proposed_memory or event.raw_or_redacted_content or "[empty event]"


@dataclass(frozen=True, slots=True)
class ReferenceMemoryRecord:
    """One record in the local reference memory store."""

    channel: str
    key: str
    value: str
    source_event_id: str
    source_authority: SourceAuthority

    def __post_init__(self) -> None:
        _require_string(self.channel, "channel", allow_empty=False, max_chars=128)
        if self.channel not in {
            REFERENCE_CHANNEL_NATIVE,
            REFERENCE_CHANNEL_GOVERNED,
        }:
            raise ValueError("channel must be a known reference store channel")
        _require_string(self.key, "key", allow_empty=False, max_chars=16_384)
        _require_string(self.value, "value", allow_empty=False, max_chars=16_384)
        _require_string(
            self.source_event_id,
            "source_event_id",
            allow_empty=False,
            max_chars=96,
        )
        object.__setattr__(
            self,
            "source_authority",
            _coerce_enum(SourceAuthority, self.source_authority, "source_authority"),
        )

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable reference record."""

        return {
            "channel": self.channel,
            "key": self.key,
            "value": self.value,
            "source_event_id": self.source_event_id,
            "source_authority": self.source_authority.value,
        }


class SQLiteReferenceMemoryStore:
    """Small SQLite store used only by the reference proxy demo."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(path))
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_records (
                channel TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                source_event_id TEXT NOT NULL,
                source_authority TEXT NOT NULL,
                PRIMARY KEY (channel, key)
            )
            """
        )
        self._connection.commit()

    def close(self) -> None:
        """Close the backing SQLite connection."""

        self._connection.close()

    def upsert_event(self, channel: str, event: MemoryEvent) -> ReferenceMemoryRecord:
        """Write a MemoryEvent into one reference-store channel."""

        record = ReferenceMemoryRecord(
            channel=channel,
            key=_memory_key_from_event(event),
            value=_memory_value_from_event(event),
            source_event_id=event.event_id,
            source_authority=event.source_authority,
        )
        self._upsert(record)
        return record

    def upsert_assertion(
        self,
        channel: str,
        assertion: MemoryStateAssertion,
    ) -> ReferenceMemoryRecord:
        """Write a state assertion into one reference-store channel."""

        record = ReferenceMemoryRecord(
            channel=channel,
            key=f"{assertion.subject}::{assertion.predicate}",
            value=assertion.object_value,
            source_event_id=assertion.source_event_id,
            source_authority=assertion.source_authority,
        )
        self._upsert(record)
        return record

    def _upsert(self, record: ReferenceMemoryRecord) -> None:
        self._connection.execute(
            """
            INSERT INTO memory_records (
                channel,
                key,
                value,
                source_event_id,
                source_authority
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(channel, key) DO UPDATE SET
                value = excluded.value,
                source_event_id = excluded.source_event_id,
                source_authority = excluded.source_authority
            """,
            (
                record.channel,
                record.key,
                record.value,
                record.source_event_id,
                record.source_authority.value,
            ),
        )
        self._connection.commit()

    def read(self, channel: str, key: str) -> ReferenceMemoryRecord | None:
        """Read one record from a channel by key."""

        row = self._connection.execute(
            """
            SELECT channel, key, value, source_event_id, source_authority
            FROM memory_records
            WHERE channel = ? AND key = ?
            """,
            (channel, key),
        ).fetchone()
        if row is None:
            return None
        return self._record_from_row(row)

    def records(self, channel: str) -> tuple[ReferenceMemoryRecord, ...]:
        """Return all records in one channel in deterministic key order."""

        rows = self._connection.execute(
            """
            SELECT channel, key, value, source_event_id, source_authority
            FROM memory_records
            WHERE channel = ?
            ORDER BY key
            """,
            (channel,),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    @staticmethod
    def _record_from_row(row: Any) -> ReferenceMemoryRecord:
        return ReferenceMemoryRecord(
            channel=str(row[0]),
            key=str(row[1]),
            value=str(row[2]),
            source_event_id=str(row[3]),
            source_authority=SourceAuthority(str(row[4])),
        )
