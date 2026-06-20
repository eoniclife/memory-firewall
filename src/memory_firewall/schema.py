"""Machine-readable schemas for the public product contract."""

from __future__ import annotations

from typing import Any

from .adapters import AdapterCapability
from .claim_budget import claim_budget
from .detectors import DETECTOR_PACK_VERSION, default_detector_pack
from .models import (
    EvidenceField,
    MAX_METADATA_ENTRIES,
    MAX_METADATA_KEY_CHARS,
    MAX_METADATA_STRING_CHARS,
    MAX_TEXT_FIELD_CHARS,
    MemoryOperation,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    SourceType,
)
from .taxonomy import risk_taxonomy
from .version import __version__

SCHEMA_VERSION = "mf-04"


def _enum_values(enum_type: type[Any]) -> list[str]:
    return [item.value for item in enum_type]


def _metadata_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "maxProperties": MAX_METADATA_ENTRIES,
        "propertyNames": {"type": "string", "maxLength": MAX_METADATA_KEY_CHARS},
        "additionalProperties": {
            "type": ["string", "number", "integer", "boolean", "null"],
            "maxLength": MAX_METADATA_STRING_CHARS,
        },
    }


def _capability_disjointness_constraints() -> list[dict[str, Any]]:
    return [
        {
            "not": {
                "required": ["supported_capabilities", "unsupported_capabilities"],
                "properties": {
                    "supported_capabilities": {"contains": {"const": capability.value}},
                    "unsupported_capabilities": {
                        "contains": {"const": capability.value}
                    },
                },
            }
        }
        for capability in AdapterCapability
    ]


def event_schema() -> dict[str, Any]:
    """Return the canonical MemoryEvent JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/memory-event.mf-04.json",
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
                "format": "date-time",
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
            "raw_or_redacted_content": {
                "type": "string",
                "maxLength": MAX_TEXT_FIELD_CHARS,
            },
            "proposed_memory": {"type": "string", "maxLength": MAX_TEXT_FIELD_CHARS},
            "operation": {"type": "string", "enum": _enum_values(MemoryOperation)},
            "target_namespace": {
                "type": "string",
                "minLength": 1,
                "maxLength": 16384,
            },
            "metadata": _metadata_schema(),
        },
    }


def evidence_span_schema() -> dict[str, Any]:
    """Return the structured evidence span JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/evidence-span.mf-04.json",
        "title": "EvidenceSpan",
        "type": "object",
        "additionalProperties": False,
        "required": ["source_field", "start", "end", "quote"],
        "properties": {
            "source_field": {"type": "string", "enum": _enum_values(EvidenceField)},
            "start": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_TEXT_FIELD_CHARS - 1,
            },
            "end": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_TEXT_FIELD_CHARS,
            },
            "quote": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_TEXT_FIELD_CHARS,
            },
        },
    }


def _policy_recommendation_payload_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "recommended_disposition",
            "reason_codes",
            "policy_version",
        ],
        "properties": {
            "finding_id": {"type": "string", "minLength": 1},
            "recommended_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "policy_version": {"const": "mf-03"},
        },
    }


def finding_schema() -> dict[str, Any]:
    """Return the canonical MemoryFinding JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/memory-finding.mf-04.json",
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
            "finding_id": {"type": "string", "minLength": 1, "maxLength": 96},
            "event_id": {"type": "string", "minLength": 1},
            "risk_category": {"type": "string", "enum": _enum_values(RiskCategory)},
            "severity": {"type": "string", "enum": _enum_values(RiskSeverity)},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_span": evidence_span_schema(),
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
    """Return the adapter capability report JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-capability-report.mf-04.json",
        "title": "AdapterCapabilityReport",
        "type": "object",
        "additionalProperties": False,
        "allOf": _capability_disjointness_constraints(),
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
            "metadata": _metadata_schema(),
        },
    }


def policy_schema() -> dict[str, Any]:
    """Return the deterministic policy JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/policy.mf-04.json",
        "title": "PolicyContract",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "policy_version",
            "severity_order",
            "disposition_order",
            "config_schema",
            "recommendation_schema",
        ],
        "properties": {
            "policy_version": {"const": "mf-03"},
            "severity_order": {
                "const": [
                    RiskSeverity.INFORMATIONAL.value,
                    RiskSeverity.SUSPICIOUS.value,
                    RiskSeverity.HIGH_IMPACT.value,
                ],
            },
            "disposition_order": {
                "const": [
                    RecommendedDisposition.PASS.value,
                    RecommendedDisposition.WARN.value,
                    RecommendedDisposition.REVIEW.value,
                    RecommendedDisposition.QUARANTINE.value,
                ],
            },
            "config_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "suspicious_review_confidence",
                    "high_impact_quarantine_confidence",
                    "metadata",
                ],
                "properties": {
                    "suspicious_review_confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "high_impact_quarantine_confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "metadata": _metadata_schema(),
                },
            },
            "recommendation_schema": _policy_recommendation_payload_schema(),
        },
    }


def detector_pack_schema() -> dict[str, Any]:
    """Return the MF-04 detector pack metadata schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/detector-pack.mf-04.json",
        "title": "DetectorPack",
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "version", "definitions"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "version": {"const": DETECTOR_PACK_VERSION},
            "definitions": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "name",
                        "version",
                        "risk_category",
                        "description",
                        "limitations",
                    ],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "version": {"const": DETECTOR_PACK_VERSION},
                        "risk_category": {
                            "type": "string",
                            "enum": _enum_values(RiskCategory),
                        },
                        "description": {"type": "string", "minLength": 1},
                        "limitations": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1},
                        },
                    },
                },
            },
        },
    }


def detector_result_schema() -> dict[str, Any]:
    """Return the MF-04 detector run result schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/detector-result.mf-04.json",
        "title": "DetectorResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "event_id",
            "pack_name",
            "pack_version",
            "findings",
            "policy_recommendations",
        ],
        "properties": {
            "event_id": {"type": "string", "minLength": 1},
            "pack_name": {"type": "string", "minLength": 1},
            "pack_version": {"const": DETECTOR_PACK_VERSION},
            "findings": {"type": "array", "items": finding_schema()},
            "policy_recommendations": {
                "type": "array",
                "items": _policy_recommendation_payload_schema(),
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
        "evidence_span_schema": evidence_span_schema(),
        "finding_schema": finding_schema(),
        "adapter_capability_report_schema": adapter_capability_report_schema(),
        "policy_schema": policy_schema(),
        "detector_pack_schema": detector_pack_schema(),
        "detector_result_schema": detector_result_schema(),
        "default_detector_pack": default_detector_pack().to_dict(),
        "risk_taxonomy": [item.to_dict() for item in risk_taxonomy()],
        "claim_budget": claim_budget().to_dict(),
    }
