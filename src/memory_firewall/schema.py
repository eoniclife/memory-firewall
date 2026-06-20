"""Machine-readable schemas for the public product contract."""

from __future__ import annotations

from typing import Any

from .adapters import AdapterCapability
from .analysis import ANALYSIS_VERSION, TrustedStateAction
from .claim_budget import claim_budget
from .detectors import DETECTOR_PACK_NAME, DETECTOR_PACK_VERSION, default_detector_pack
from .models import (
    EvidenceField,
    MAX_METADATA_ENTRIES,
    MAX_METADATA_KEY_CHARS,
    MAX_METADATA_STRING_CHARS,
    MAX_TEXT_FIELD_CHARS,
    MemoryOperation,
    RFC3339_TIMESTAMP_PATTERN,
    RecommendedDisposition,
    RiskCategory,
    RiskSeverity,
    SourceAuthority,
    SourceType,
)
from .scan import SCAN_ISSUE_ID_PREFIX, SCAN_VERSION, ScanEventLevel
from .taxonomy import risk_taxonomy
from .version import __version__

SCHEMA_VERSION = "mf-06"


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
                "description": "RFC 3339 timestamp supplied by the adapter.",
                "format": "date-time",
                "pattern": RFC3339_TIMESTAMP_PATTERN,
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

    built_in_detector_definitions = [
        definition.to_dict() for definition in default_detector_pack().definitions
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/detector-pack.mf-04.json",
        "title": "DetectorPack",
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "version", "definitions"],
        "properties": {
            "name": {"const": DETECTOR_PACK_NAME},
            "version": {"const": DETECTOR_PACK_VERSION},
            "definitions": {"const": built_in_detector_definitions},
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
            "pack_name": {"const": DETECTOR_PACK_NAME},
            "pack_version": {"const": DETECTOR_PACK_VERSION},
            "findings": {"type": "array", "items": finding_schema()},
            "policy_recommendations": {
                "type": "array",
                "items": _policy_recommendation_payload_schema(),
            },
        },
    }


def state_assertion_schema() -> dict[str, Any]:
    """Return the MF-05 local state assertion schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/state-assertion.mf-05.json",
        "title": "MemoryStateAssertion",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "assertion_id",
            "subject",
            "predicate",
            "object_value",
            "object_hash_sha256",
            "object_redacted",
            "source_event_id",
            "source_authority",
            "asserted_at",
            "status",
            "supersedes",
            "metadata",
        ],
        "properties": {
            "assertion_id": {"type": "string", "minLength": 1, "maxLength": 96},
            "subject": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_FIELD_CHARS},
            "predicate": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_FIELD_CHARS},
            "object_value": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_FIELD_CHARS},
            "object_hash_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "object_redacted": {"type": "boolean"},
            "source_event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "source_authority": {"type": "string", "enum": _enum_values(SourceAuthority)},
            "asserted_at": {
                "type": "string",
                "format": "date-time",
                "pattern": RFC3339_TIMESTAMP_PATTERN,
            },
            "status": {
                "type": "string",
                "enum": ["candidate", "trusted", "superseded"],
            },
            "supersedes": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "uniqueItems": True,
            },
            "metadata": _metadata_schema(),
        },
    }


def state_analysis_schema() -> dict[str, Any]:
    """Return the MF-05 state-analysis result schema."""

    contradiction_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "existing_assertion_id",
            "candidate_assertion_id",
            "subject",
            "predicate",
            "existing_object_hash_sha256",
            "candidate_object_hash_sha256",
            "existing_source_authority",
            "candidate_source_authority",
            "existing_status",
        ],
        "properties": {
            "existing_assertion_id": {"type": "string", "minLength": 1},
            "candidate_assertion_id": {"type": "string", "minLength": 1},
            "subject": {"type": "string", "minLength": 1},
            "predicate": {"type": "string", "minLength": 1},
            "existing_object_hash_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "candidate_object_hash_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "existing_source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
            "candidate_source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
            "existing_status": {
                "type": "string",
                "enum": ["candidate", "trusted", "superseded"],
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/state-analysis.mf-05.json",
        "title": "StateAnalysisResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "analysis_id",
            "analysis_version",
            "event_id",
            "assertion",
            "authority_assessment",
            "contradictions",
            "supersession_candidate_ids",
            "trusted_state_action",
            "reason_codes",
            "limitations",
            "finding_ids",
            "amc_mapping",
        ],
        "properties": {
            "analysis_id": {"type": "string", "pattern": "^mfanalysis_v1_[0-9a-f]{32}$"},
            "analysis_version": {"const": ANALYSIS_VERSION},
            "event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "assertion": state_assertion_schema(),
            "authority_assessment": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_authority",
                    "rank",
                    "can_enter_candidate_plane",
                    "can_skip_reducer_review",
                    "reason_codes",
                ],
                "properties": {
                    "source_authority": {
                        "type": "string",
                        "enum": _enum_values(SourceAuthority),
                    },
                    "rank": {"type": "integer", "minimum": 0, "maximum": 5},
                    "can_enter_candidate_plane": {"type": "boolean"},
                    "can_skip_reducer_review": {"const": False},
                    "reason_codes": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
            "contradictions": {"type": "array", "items": contradiction_schema},
            "supersession_candidate_ids": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "uniqueItems": True,
            },
            "trusted_state_action": {
                "type": "string",
                "enum": _enum_values(TrustedStateAction),
            },
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "finding_ids": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "uniqueItems": True,
            },
            "amc_mapping": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source_record", "evidence_span", "candidate_claim"],
                "properties": {
                    "source_record": {"type": "object"},
                    "evidence_span": {"type": "object"},
                    "candidate_claim": {"type": "object"},
                },
            },
        },
    }


def scan_result_schema() -> dict[str, Any]:
    """Return the MF-06 finite JSONL scan result schema."""

    issue_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["issue_id", "line_number", "error_type", "message"],
        "properties": {
            "issue_id": {
                "type": "string",
                "pattern": f"^{SCAN_ISSUE_ID_PREFIX}[0-9a-f]{{32}}$",
            },
            "line_number": {"type": "integer", "minimum": 1},
            "error_type": {"type": "string", "minLength": 1},
            "message": {"const": "line could not be parsed as a valid MemoryEvent"},
        },
    }
    event_result_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "line_number",
            "event_id",
            "level",
            "highest_disposition",
            "finding_count",
            "contradiction_count",
            "detector_result",
            "state_analysis",
        ],
        "properties": {
            "line_number": {"type": "integer", "minimum": 1},
            "event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "level": {
                "type": "string",
                "enum": _enum_values(ScanEventLevel),
            },
            "highest_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "finding_count": {"type": "integer", "minimum": 0},
            "contradiction_count": {"type": "integer", "minimum": 0},
            "detector_result": detector_result_schema(),
            "state_analysis": state_analysis_schema(),
        },
    }
    summary_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "total_lines",
            "analyzed_events",
            "invalid_lines",
            "pass_events",
            "warn_events",
            "high_risk_events",
            "total_findings",
            "blocked_low_authority_contradictions",
            "highest_disposition",
        ],
        "properties": {
            "total_lines": {"type": "integer", "minimum": 0},
            "analyzed_events": {"type": "integer", "minimum": 0},
            "invalid_lines": {"type": "integer", "minimum": 0},
            "pass_events": {"type": "integer", "minimum": 0},
            "warn_events": {"type": "integer", "minimum": 0},
            "high_risk_events": {"type": "integer", "minimum": 0},
            "total_findings": {"type": "integer", "minimum": 0},
            "blocked_low_authority_contradictions": {
                "type": "integer",
                "minimum": 0,
            },
            "highest_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/scan-result.mf-06.json",
        "title": "ScanResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "scan_version",
            "source",
            "summary",
            "events",
            "issues",
            "metadata",
        ],
        "properties": {
            "scan_version": {"const": SCAN_VERSION},
            "source": {"type": "string", "minLength": 1},
            "summary": summary_schema,
            "events": {"type": "array", "items": event_result_schema},
            "issues": {"type": "array", "items": issue_schema},
            "metadata": {
                "type": "object",
                "additionalProperties": True,
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
        "state_assertion_schema": state_assertion_schema(),
        "state_analysis_schema": state_analysis_schema(),
        "scan_result_schema": scan_result_schema(),
        "default_detector_pack": default_detector_pack().to_dict(),
        "risk_taxonomy": [item.to_dict() for item in risk_taxonomy()],
        "claim_budget": claim_budget().to_dict(),
    }
