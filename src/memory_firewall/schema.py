"""Machine-readable schemas for the public product contract."""

from __future__ import annotations

from typing import Any

from .adapters import AdapterCapability
from .claim_budget import claim_budget
from .models import (
    MemoryOperation,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    SourceType,
)
from .taxonomy import risk_taxonomy
from .version import __version__

SCHEMA_VERSION = "mf-02"


def _enum_values(enum_type: type[Any]) -> list[str]:
    return [item.value for item in enum_type]


def event_schema() -> dict[str, Any]:
    """Return the canonical MemoryEvent JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/memory-event.mf-02.json",
        "title": "MemoryEvent",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "event_id",
            "timestamp",
            "actor",
            "user_or_tenant_scope",
            "source_type",
            "source_id",
            "source_authority",
            "raw_or_redacted_content",
            "proposed_memory",
            "operation",
            "target_namespace",
            "metadata",
        ],
        "properties": {
            "event_id": {"type": "string", "minLength": 1, "maxLength": 96},
            "timestamp": {
                "type": "string",
                "description": "RFC 3339 / ISO 8601 timestamp supplied by the adapter.",
                "minLength": 1,
                "maxLength": 16384,
            },
            "actor": {"type": "string", "minLength": 1, "maxLength": 16384},
            "user_or_tenant_scope": {
                "type": "string",
                "minLength": 1,
                "maxLength": 16384,
            },
            "source_type": {"type": "string", "enum": _enum_values(SourceType)},
            "source_id": {"type": "string", "minLength": 1, "maxLength": 16384},
            "source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
            "raw_or_redacted_content": {"type": "string", "maxLength": 16384},
            "proposed_memory": {"type": "string", "maxLength": 16384},
            "operation": {"type": "string", "enum": _enum_values(MemoryOperation)},
            "target_namespace": {
                "type": "string",
                "minLength": 1,
                "maxLength": 16384,
            },
            "metadata": {
                "type": "object",
                "maxProperties": 64,
                "propertyNames": {"type": "string", "maxLength": 128},
                "additionalProperties": {
                    "type": ["string", "number", "integer", "boolean", "null"],
                    "maxLength": 4096,
                },
            },
        },
    }


def finding_schema() -> dict[str, Any]:
    """Return the canonical MemoryFinding JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/memory-finding.mf-02.json",
        "title": "MemoryFinding",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "event_id",
            "risk_category",
            "severity",
            "confidence",
            "evidence_span",
            "detector_name",
            "detector_version",
            "explanation",
            "recommended_disposition",
            "limitations",
        ],
        "properties": {
            "finding_id": {"type": "string", "minLength": 1},
            "event_id": {"type": "string", "minLength": 1},
            "risk_category": {"type": "string", "enum": _enum_values(RiskCategory)},
            "severity": {"type": "string", "enum": _enum_values(RiskSeverity)},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_span": {"type": "string"},
            "detector_name": {"type": "string", "minLength": 1},
            "detector_version": {"type": "string", "minLength": 1},
            "explanation": {"type": "string", "minLength": 1},
            "recommended_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "limitations": {"type": "array", "items": {"type": "string"}},
        },
    }


def adapter_capability_report_schema() -> dict[str, Any]:
    """Return the MF-02 adapter capability report JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-capability-report.mf-02.json",
        "title": "AdapterCapabilityReport",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "adapter_name",
            "adapter_version",
            "supported_capabilities",
            "unsupported_capabilities",
            "notes",
            "metadata",
        ],
        "properties": {
            "adapter_name": {"type": "string", "minLength": 1, "maxLength": 256},
            "adapter_version": {"type": "string", "minLength": 1, "maxLength": 128},
            "supported_capabilities": {
                "type": "array",
                "items": {"type": "string", "enum": _enum_values(AdapterCapability)},
                "uniqueItems": True,
            },
            "unsupported_capabilities": {
                "type": "array",
                "items": {"type": "string", "enum": _enum_values(AdapterCapability)},
                "uniqueItems": True,
            },
            "notes": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "metadata": {
                "type": "object",
                "maxProperties": 64,
                "propertyNames": {"type": "string", "maxLength": 128},
                "additionalProperties": {
                    "type": ["string", "number", "integer", "boolean", "null"],
                    "maxLength": 4096,
                },
            },
        },
    }


def schema_bundle() -> dict[str, Any]:
    """Return the complete public contract bundle."""

    return {
        "package": "memory-firewall",
        "package_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "event_schema": event_schema(),
        "finding_schema": finding_schema(),
        "adapter_capability_report_schema": adapter_capability_report_schema(),
        "risk_taxonomy": [item.to_dict() for item in risk_taxonomy()],
        "claim_budget": claim_budget().to_dict(),
    }
