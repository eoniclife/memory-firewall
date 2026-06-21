"""Machine-readable schemas for the public product contract."""

from __future__ import annotations

from typing import Any

from .adapter_bridge import ADAPTER_BRIDGE_REPORT_VERSION, ADAPTER_BRIDGE_VERSION
from .adapters import AdapterCapability
from .analysis import ANALYSIS_VERSION, TrustedStateAction
from .claim_budget import claim_budget
from .detectors import DETECTOR_PACK_NAME, DETECTOR_PACK_VERSION, default_detector_pack
from .demo import POISON_DEMO_VERSION
from .hermes import (
    HERMES_DEFAULT_MODE,
    HERMES_INTEGRATION_VERSION,
    HERMES_OBSERVATION_SCOPE_ALL,
    HERMES_OBSERVATION_SCOPE_CURRENT_VERSION,
    HERMES_REPORT_VERSION,
)
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
from .proxy import REFERENCE_PROXY_VERSION, ProxyMode
from .reference_store import REFERENCE_CHANNEL_GOVERNED, REFERENCE_CHANNEL_NATIVE
from .report import REDACTED_EXPORT_VERSION, REPORT_VERSION
from .review import (
    OVERRIDE_RECEIPT_ID_PREFIX,
    REVIEW_ITEM_ID_PREFIX,
    REVIEW_VERSION,
    TRUSTED_READ_PREVIEW_STATUS,
    OverrideDecision,
    ReviewItemStatus,
)
from .scan import SCAN_ISSUE_ID_PREFIX, SCAN_VERSION, ScanEventLevel
from .taxonomy import risk_taxonomy
from .version import __version__

SCHEMA_VERSION = "mf-23"


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


def _review_finding_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "risk_category",
            "severity",
            "recommended_disposition",
            "detector_name",
            "explanation",
            "limitations",
        ],
        "properties": {
            "finding_id": {"type": "string", "minLength": 1, "maxLength": 96},
            "risk_category": {"type": "string", "enum": _enum_values(RiskCategory)},
            "severity": {"type": "string", "enum": _enum_values(RiskSeverity)},
            "recommended_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "detector_name": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_TEXT_FIELD_CHARS,
            },
            "explanation": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_TEXT_FIELD_CHARS,
            },
            "limitations": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def override_receipt_schema() -> dict[str, Any]:
    """Return the MF-07 local override receipt schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/override-receipt.mf-07.json",
        "title": "OverrideReceipt",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "receipt_id",
            "receipt_version",
            "item_id",
            "item_hash_sha256",
            "decision",
            "reason",
            "reviewer",
            "event_id",
            "assertion_id",
            "finding_ids",
            "metadata",
        ],
        "properties": {
            "receipt_id": {
                "type": "string",
                "pattern": f"^{OVERRIDE_RECEIPT_ID_PREFIX}[0-9a-f]{{32}}$",
            },
            "receipt_version": {"const": REVIEW_VERSION},
            "item_id": {
                "type": "string",
                "pattern": f"^{REVIEW_ITEM_ID_PREFIX}[0-9a-f]{{32}}$",
            },
            "item_hash_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "decision": {"type": "string", "enum": _enum_values(OverrideDecision)},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            "reviewer": {"type": "string", "minLength": 1, "maxLength": 256},
            "event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "assertion_id": {
                "type": "string",
                "pattern": "^mfassert_v1_[0-9a-f]{32}$",
            },
            "finding_ids": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "metadata": _metadata_schema(),
        },
    }


def _review_item_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "item_id",
            "item_hash_sha256",
            "review_version",
            "source",
            "line_number",
            "event_id",
            "level",
            "highest_disposition",
            "finding_count",
            "contradiction_count",
            "analysis_id",
            "trusted_state_action",
            "assertion",
            "reason_codes",
            "finding_summaries",
            "status",
            "receipt_id",
            "metadata",
        ],
        "properties": {
            "item_id": {
                "type": "string",
                "pattern": f"^{REVIEW_ITEM_ID_PREFIX}[0-9a-f]{{32}}$",
            },
            "item_hash_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "review_version": {"const": REVIEW_VERSION},
            "source": {"type": "string", "minLength": 1},
            "line_number": {"type": "integer", "minimum": 1},
            "event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "level": {"const": ScanEventLevel.HIGH_RISK.value},
            "highest_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "finding_count": {"type": "integer", "minimum": 0},
            "contradiction_count": {"type": "integer", "minimum": 0},
            "analysis_id": {
                "type": "string",
                "pattern": "^mfanalysis_v1_[0-9a-f]{32}$",
            },
            "trusted_state_action": {
                "type": "string",
                "enum": _enum_values(TrustedStateAction),
            },
            "assertion": state_assertion_schema(),
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "finding_summaries": {
                "type": "array",
                "items": _review_finding_summary_schema(),
            },
            "status": {"type": "string", "enum": _enum_values(ReviewItemStatus)},
            "receipt_id": {
                "anyOf": [
                    {
                        "type": "string",
                        "pattern": f"^{OVERRIDE_RECEIPT_ID_PREFIX}[0-9a-f]{{32}}$",
                    },
                    {"type": "null"},
                ],
            },
            "metadata": _metadata_schema(),
        },
    }


def review_queue_schema() -> dict[str, Any]:
    """Return the MF-07 local review queue schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/review-queue.mf-07.json",
        "title": "ReviewQueue",
        "type": "object",
        "additionalProperties": False,
        "required": ["review_version", "items", "receipts", "metadata"],
        "properties": {
            "review_version": {"const": REVIEW_VERSION},
            "items": {"type": "array", "items": _review_item_schema()},
            "receipts": {"type": "array", "items": override_receipt_schema()},
            "metadata": _metadata_schema(),
        },
    }


def trusted_read_preview_schema() -> dict[str, Any]:
    """Return the MF-07 local trusted-read preview schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/trusted-read-preview.mf-07.json",
        "title": "TrustedReadPreview",
        "type": "object",
        "additionalProperties": False,
        "required": ["preview_version", "items", "limitations", "metadata"],
        "properties": {
            "preview_version": {"const": REVIEW_VERSION},
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "item_id",
                        "event_id",
                        "assertion",
                        "receipt",
                        "preview_status",
                    ],
                    "properties": {
                        "item_id": {
                            "type": "string",
                            "pattern": f"^{REVIEW_ITEM_ID_PREFIX}[0-9a-f]{{32}}$",
                        },
                        "event_id": {
                            "type": "string",
                            "pattern": "^mfev_v1_[0-9a-f]{32}$",
                        },
                        "assertion": state_assertion_schema(),
                        "receipt": override_receipt_schema(),
                        "preview_status": {"const": TRUSTED_READ_PREVIEW_STATUS},
                    },
                },
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "metadata": _metadata_schema(),
        },
    }


def demo_result_schema() -> dict[str, Any]:
    """Return the MF-08 local poisoning demo result schema."""

    naive_write_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["key", "value", "source_event_id", "source_authority"],
        "properties": {
            "key": {"type": "string", "minLength": 1},
            "value": {"type": "string", "minLength": 1},
            "source_event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
        },
    }
    naive_read_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["key", "value", "source_event_id"],
        "properties": {
            "key": {"type": "string", "minLength": 1},
            "value": {"type": "string", "minLength": 1},
            "source_event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
        },
    }
    outcome_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "naive_answer",
            "source_of_record_answer",
            "naive_memory_was_poisoned",
            "benign_memory_passed",
            "firewall_high_risk_events",
            "firewall_high_risk_event_ids",
            "queued_items",
            "pending_preview_items",
            "rejected_preview_items",
            "override_preview_items",
            "default_path_excludes_unreviewed_memory",
            "reject_path_excludes_forged_memory",
            "override_path_requires_receipt",
        ],
        "properties": {
            "naive_answer": {"type": "string", "minLength": 1},
            "source_of_record_answer": {"type": "string", "minLength": 1},
            "naive_memory_was_poisoned": {"type": "boolean"},
            "benign_memory_passed": {"type": "boolean"},
            "firewall_high_risk_events": {"type": "integer", "minimum": 0},
            "firewall_high_risk_event_ids": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^mfev_v1_[0-9a-f]{32}$",
                },
                "uniqueItems": True,
            },
            "queued_items": {"type": "integer", "minimum": 0},
            "pending_preview_items": {"type": "integer", "minimum": 0},
            "rejected_preview_items": {"type": "integer", "minimum": 0},
            "override_preview_items": {"type": "integer", "minimum": 0},
            "default_path_excludes_unreviewed_memory": {"type": "boolean"},
            "reject_path_excludes_forged_memory": {"type": "boolean"},
            "override_path_requires_receipt": {"type": "boolean"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/demo-result.mf-08.json",
        "title": "PoisonDemoResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "demo_version",
            "scenario",
            "events",
            "naive_store",
            "memory_firewall",
            "outcome",
            "limitations",
        ],
        "properties": {
            "demo_version": {"const": POISON_DEMO_VERSION},
            "scenario": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "scenario_id",
                    "memory_key",
                    "source_of_record_value",
                    "forged_value",
                    "question",
                    "description",
                ],
                "properties": {
                    "scenario_id": {"type": "string", "minLength": 1},
                    "memory_key": {"type": "string", "minLength": 1},
                    "source_of_record_value": {"type": "string", "minLength": 1},
                    "forged_value": {"type": "string", "minLength": 1},
                    "question": {"type": "string", "minLength": 1},
                    "description": {"type": "string", "minLength": 1},
                },
            },
            "events": {
                "type": "array",
                "minItems": 1,
                "items": event_schema(),
            },
            "naive_store": {
                "type": "object",
                "additionalProperties": False,
                "required": ["contract", "writes", "read_after_poison"],
                "properties": {
                    "contract": {"const": "toy_last_write_wins_store"},
                    "writes": {"type": "array", "items": naive_write_schema},
                    "read_after_poison": naive_read_schema,
                },
            },
            "memory_firewall": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "scan_result",
                    "review_queue",
                    "pending_preview",
                    "rejected_preview",
                    "override_preview",
                ],
                "properties": {
                    "scan_result": scan_result_schema(),
                    "review_queue": review_queue_schema(),
                    "pending_preview": trusted_read_preview_schema(),
                    "rejected_preview": trusted_read_preview_schema(),
                    "override_preview": trusted_read_preview_schema(),
                },
            },
            "outcome": outcome_schema,
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def _reference_memory_record_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "channel",
            "key",
            "value",
            "source_event_id",
            "source_authority",
        ],
        "properties": {
            "channel": {
                "type": "string",
                "enum": [REFERENCE_CHANNEL_NATIVE, REFERENCE_CHANNEL_GOVERNED],
            },
            "key": {"type": "string", "minLength": 1},
            "value": {"type": "string", "minLength": 1},
            "source_event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
        },
    }


def reference_proxy_result_schema() -> dict[str, Any]:
    """Return the MF-09 reference proxy result schema."""

    write_decision_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "event_id",
            "line_number",
            "level",
            "native_write",
            "governed_context_write",
            "reason_codes",
            "review_item_id",
        ],
        "properties": {
            "event_id": {"type": "string", "pattern": "^mfev_v1_[0-9a-f]{32}$"},
            "line_number": {"type": "integer", "minimum": 1},
            "level": {"type": "string", "enum": _enum_values(ScanEventLevel)},
            "native_write": {"type": "boolean"},
            "governed_context_write": {"type": "boolean"},
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "review_item_id": {
                "anyOf": [
                    {
                        "type": "string",
                        "pattern": f"^{REVIEW_ITEM_ID_PREFIX}[0-9a-f]{{32}}$",
                    },
                    {"type": "null"},
                ],
            },
        },
    }
    nullable_record = {
        "anyOf": [_reference_memory_record_schema(), {"type": "null"}],
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/reference-proxy-result.mf-09.json",
        "title": "ReferenceProxyResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "proxy_version",
            "mode",
            "capability_report",
            "scan_result",
            "review_queue",
            "trusted_read_preview",
            "write_decisions",
            "native_records",
            "governed_context_records",
            "native_read_after_writes",
            "governed_read_after_writes",
            "outcome",
            "limitations",
        ],
        "properties": {
            "proxy_version": {"const": REFERENCE_PROXY_VERSION},
            "mode": {"type": "string", "enum": _enum_values(ProxyMode)},
            "capability_report": adapter_capability_report_schema(),
            "scan_result": scan_result_schema(),
            "review_queue": review_queue_schema(),
            "trusted_read_preview": trusted_read_preview_schema(),
            "write_decisions": {
                "type": "array",
                "minItems": 1,
                "items": write_decision_schema,
            },
            "native_records": {
                "type": "array",
                "items": _reference_memory_record_schema(),
            },
            "governed_context_records": {
                "type": "array",
                "items": _reference_memory_record_schema(),
            },
            "native_read_after_writes": nullable_record,
            "governed_read_after_writes": nullable_record,
            "outcome": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "mode",
                    "native_answer",
                    "governed_context_answer",
                    "high_risk_events",
                    "queued_items",
                    "trusted_read_preview_items",
                    "suppressed_native_event_ids",
                    "native_record_count",
                    "governed_context_record_count",
                ],
                "properties": {
                    "mode": {"type": "string", "enum": _enum_values(ProxyMode)},
                    "native_answer": {
                        "anyOf": [
                            {"type": "string", "minLength": 1},
                            {"type": "null"},
                        ],
                    },
                    "governed_context_answer": {
                        "anyOf": [
                            {"type": "string", "minLength": 1},
                            {"type": "null"},
                        ],
                    },
                    "high_risk_events": {"type": "integer", "minimum": 0},
                    "queued_items": {"type": "integer", "minimum": 0},
                    "trusted_read_preview_items": {"type": "integer", "minimum": 0},
                    "suppressed_native_event_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^mfev_v1_[0-9a-f]{32}$",
                        },
                        "uniqueItems": True,
                    },
                    "native_record_count": {"type": "integer", "minimum": 0},
                    "governed_context_record_count": {
                        "type": "integer",
                        "minimum": 0,
                    },
                },
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def _report_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "pass_events",
            "warn_events",
            "high_risk_events",
            "queued_items",
            "suppressed_native_writes",
            "redacted_share_default",
            "hosted_dashboard",
            "production_adapter_support",
        ],
        "properties": {
            "pass_events": {"type": "integer", "minimum": 0},
            "warn_events": {"type": "integer", "minimum": 0},
            "high_risk_events": {"type": "integer", "minimum": 0},
            "queued_items": {"type": "integer", "minimum": 0},
            "suppressed_native_writes": {"type": "integer", "minimum": 0},
            "redacted_share_default": {"const": True},
            "hosted_dashboard": {"const": False},
            "production_adapter_support": {"const": False},
        },
    }


def _report_event_summary_schema(*, redacted: bool) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "event_label": {"type": "string", "pattern": "^event_[0-9]+$"},
        "line_number": {"type": "integer", "minimum": 1},
        "level": {"type": "string", "enum": _enum_values(ScanEventLevel)},
        "highest_disposition": {
            "type": "string",
            "enum": _enum_values(RecommendedDisposition),
        },
        "finding_count": {"type": "integer", "minimum": 0},
        "contradiction_count": {"type": "integer", "minimum": 0},
        "risk_categories": {
            "type": "array",
            "items": {"type": "string", "enum": _enum_values(RiskCategory)},
            "uniqueItems": True,
        },
        "suppressed_native_write": {"type": "boolean"},
    }
    required = [
        "event_label",
        "line_number",
        "level",
        "highest_disposition",
        "finding_count",
        "contradiction_count",
        "risk_categories",
        "suppressed_native_write",
    ]
    if redacted:
        properties["review_item_present"] = {"type": "boolean"}
        required.append("review_item_present")
    else:
        properties["event_id"] = {
            "type": "string",
            "pattern": "^mfev_v1_[0-9a-f]{32}$",
        }
        properties["review_item_id"] = {
            "anyOf": [
                {
                    "type": "string",
                    "pattern": f"^{REVIEW_ITEM_ID_PREFIX}[0-9a-f]{{32}}$",
                },
                {"type": "null"},
            ],
        }
        required.extend(["event_id", "review_item_id"])
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _report_demo_outcome_schema(*, redacted: bool) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "naive_memory_was_poisoned": {"type": "boolean"},
        "benign_memory_passed": {"type": "boolean"},
        "firewall_high_risk_events": {"type": "integer", "minimum": 0},
        "queued_items": {"type": "integer", "minimum": 0},
        "pending_preview_items": {"type": "integer", "minimum": 0},
        "rejected_preview_items": {"type": "integer", "minimum": 0},
        "override_preview_items": {"type": "integer", "minimum": 0},
    }
    required = list(properties)
    if redacted:
        properties["answer_values_redacted"] = {"const": True}
        properties["event_ids_redacted"] = {"const": True}
        required.extend(["answer_values_redacted", "event_ids_redacted"])
    else:
        properties.update(
            {
                "naive_answer": {"type": "string", "minLength": 1},
                "source_of_record_answer": {"type": "string", "minLength": 1},
                "firewall_high_risk_event_ids": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": "^mfev_v1_[0-9a-f]{32}$",
                    },
                    "uniqueItems": True,
                },
                "default_path_excludes_unreviewed_memory": {"type": "boolean"},
                "reject_path_excludes_forged_memory": {"type": "boolean"},
                "override_path_requires_receipt": {"type": "boolean"},
            }
        )
        required.extend(
            [
                "naive_answer",
                "source_of_record_answer",
                "firewall_high_risk_event_ids",
                "default_path_excludes_unreviewed_memory",
                "reject_path_excludes_forged_memory",
                "override_path_requires_receipt",
            ]
        )
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _report_proxy_outcome_schema(*, redacted: bool) -> dict[str, Any]:
    if redacted:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "mode",
                "high_risk_events",
                "queued_items",
                "trusted_read_preview_items",
                "suppressed_native_write_count",
                "native_record_count",
                "governed_context_record_count",
                "answer_values_redacted",
                "event_ids_redacted",
            ],
            "properties": {
                "mode": {"type": "string", "enum": _enum_values(ProxyMode)},
                "high_risk_events": {"type": "integer", "minimum": 0},
                "queued_items": {"type": "integer", "minimum": 0},
                "trusted_read_preview_items": {"type": "integer", "minimum": 0},
                "suppressed_native_write_count": {"type": "integer", "minimum": 0},
                "native_record_count": {"type": "integer", "minimum": 0},
                "governed_context_record_count": {"type": "integer", "minimum": 0},
                "answer_values_redacted": {"const": True},
                "event_ids_redacted": {"const": True},
            },
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "mode",
            "native_answer",
            "governed_context_answer",
            "high_risk_events",
            "queued_items",
            "trusted_read_preview_items",
            "suppressed_native_event_ids",
            "native_record_count",
            "governed_context_record_count",
        ],
        "properties": {
            "mode": {"type": "string", "enum": _enum_values(ProxyMode)},
            "native_answer": {
                "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}],
            },
            "governed_context_answer": {
                "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}],
            },
            "high_risk_events": {"type": "integer", "minimum": 0},
            "queued_items": {"type": "integer", "minimum": 0},
            "trusted_read_preview_items": {"type": "integer", "minimum": 0},
            "suppressed_native_event_ids": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^mfev_v1_[0-9a-f]{32}$",
                },
                "uniqueItems": True,
            },
            "native_record_count": {"type": "integer", "minimum": 0},
            "governed_context_record_count": {"type": "integer", "minimum": 0},
        },
    }


def report_result_schema() -> dict[str, Any]:
    """Return the MF-10 local report schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/report-result.mf-10.json",
        "title": "ReportResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "report_version",
            "title",
            "source",
            "summary",
            "demo_outcome",
            "proxy_outcomes",
            "event_summaries",
            "capability_report",
            "limitations",
            "metadata",
        ],
        "properties": {
            "report_version": {"const": REPORT_VERSION},
            "title": {"type": "string", "minLength": 1},
            "source": {"type": "string", "minLength": 1},
            "summary": _report_summary_schema(),
            "demo_outcome": _report_demo_outcome_schema(redacted=False),
            "proxy_outcomes": {
                "type": "array",
                "minItems": 1,
                "items": _report_proxy_outcome_schema(redacted=False),
            },
            "event_summaries": {
                "type": "array",
                "minItems": 1,
                "items": _report_event_summary_schema(redacted=False),
            },
            "capability_report": adapter_capability_report_schema(),
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "metadata": _metadata_schema(),
        },
    }


def redacted_report_export_schema() -> dict[str, Any]:
    """Return the MF-10 redacted report export schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/redacted-report-export.mf-10.json",
        "title": "RedactedReportExport",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "export_version",
            "redacted",
            "title",
            "summary",
            "demo_outcome",
            "proxy_outcomes",
            "event_summaries",
            "omissions",
            "limitations",
        ],
        "properties": {
            "export_version": {"const": REDACTED_EXPORT_VERSION},
            "redacted": {"const": True},
            "title": {"type": "string", "minLength": 1},
            "summary": _report_summary_schema(),
            "demo_outcome": _report_demo_outcome_schema(redacted=True),
            "proxy_outcomes": {
                "type": "array",
                "minItems": 1,
                "items": _report_proxy_outcome_schema(redacted=True),
            },
            "event_summaries": {
                "type": "array",
                "minItems": 1,
                "items": _report_event_summary_schema(redacted=True),
            },
            "omissions": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def hermes_status_schema() -> dict[str, Any]:
    """Return the Hermes hook alpha status JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/hermes-status.mf-20.json",
        "title": "HermesStatus",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "integration_version",
            "state_dir",
            "total_observations",
            "current_version_observations",
            "legacy_version_observations",
            "high_risk_observations",
            "warn_observations",
            "pass_observations",
            "blocked_by_firewall",
            "latest_recorded_at",
            "mode",
            "observe_only",
            "production_enforcement",
        ],
        "properties": {
            "integration_version": {"const": HERMES_INTEGRATION_VERSION},
            "state_dir": {"type": "string", "minLength": 1},
            "total_observations": {"type": "integer", "minimum": 0},
            "current_version_observations": {"type": "integer", "minimum": 0},
            "legacy_version_observations": {"type": "integer", "minimum": 0},
            "high_risk_observations": {"type": "integer", "minimum": 0},
            "warn_observations": {"type": "integer", "minimum": 0},
            "pass_observations": {"type": "integer", "minimum": 0},
            "blocked_by_firewall": {"type": "integer", "minimum": 0},
            "latest_recorded_at": {
                "anyOf": [
                    {
                        "type": "string",
                        "format": "date-time",
                        "pattern": RFC3339_TIMESTAMP_PATTERN,
                    },
                    {"type": "null"},
                ],
            },
            "mode": {"const": HERMES_DEFAULT_MODE},
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
        },
    }


def _hermes_observation_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "integration_version",
            "recorded_integration_version",
            "row_number",
            "recorded_at",
            "hook_name",
            "tool_name",
            "mode",
            "blocked_by_firewall",
            "event_ref",
            "operation",
            "source_authority",
            "target_namespace",
            "level",
            "highest_disposition",
            "finding_count",
            "contradiction_count",
            "risk_categories",
            "detector_names",
        ],
        "properties": {
            "integration_version": {"const": HERMES_INTEGRATION_VERSION},
            "recorded_integration_version": {"type": "string", "minLength": 1},
            "row_number": {"type": "integer", "minimum": 1},
            "recorded_at": {
                "anyOf": [
                    {
                        "type": "string",
                        "format": "date-time",
                        "pattern": RFC3339_TIMESTAMP_PATTERN,
                    },
                    {"const": "unavailable-recorded-at"},
                ],
            },
            "hook_name": {"type": "string", "minLength": 1},
            "tool_name": {"type": "string", "minLength": 1},
            "mode": {"const": HERMES_DEFAULT_MODE},
            "blocked_by_firewall": {"type": "boolean"},
            "event_ref": {
                "type": "string",
                "pattern": r"^observation-row-[1-9][0-9]*$",
            },
            "operation": {"type": "string", "enum": _enum_values(MemoryOperation)},
            "source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
            "target_namespace": {"type": "string", "minLength": 1},
            "level": {"type": "string", "enum": _enum_values(ScanEventLevel)},
            "highest_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "finding_count": {"type": "integer", "minimum": 0},
            "contradiction_count": {"type": "integer", "minimum": 0},
            "risk_categories": {
                "type": "array",
                "items": {"type": "string", "enum": _enum_values(RiskCategory)},
            },
            "detector_names": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def hermes_observations_schema() -> dict[str, Any]:
    """Return the redacted Hermes observations list JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/hermes-observations.mf-20.json",
        "title": "HermesObservations",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "integration_version",
            "state_dir",
            "observation_scope",
            "limit",
            "total_observations",
            "high_risk_observations",
            "warn_observations",
            "pass_observations",
            "matching_observations",
            "matching_high_risk_observations",
            "matching_warn_observations",
            "matching_pass_observations",
            "returned_observations",
            "observations",
            "mode",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ],
        "properties": {
            "integration_version": {"const": HERMES_INTEGRATION_VERSION},
            "state_dir": {"type": "string", "minLength": 1},
            "observation_scope": {
                "type": "string",
                "enum": [
                    HERMES_OBSERVATION_SCOPE_ALL,
                    HERMES_OBSERVATION_SCOPE_CURRENT_VERSION,
                ],
            },
            "limit": {"type": "integer", "minimum": 1},
            "total_observations": {"type": "integer", "minimum": 0},
            "high_risk_observations": {"type": "integer", "minimum": 0},
            "warn_observations": {"type": "integer", "minimum": 0},
            "pass_observations": {"type": "integer", "minimum": 0},
            "matching_observations": {"type": "integer", "minimum": 0},
            "matching_high_risk_observations": {"type": "integer", "minimum": 0},
            "matching_warn_observations": {"type": "integer", "minimum": 0},
            "matching_pass_observations": {"type": "integer", "minimum": 0},
            "returned_observations": {"type": "integer", "minimum": 0},
            "observations": {
                "type": "array",
                "items": _hermes_observation_summary_schema(),
            },
            "mode": {"const": HERMES_DEFAULT_MODE},
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
        },
    }


def _adapter_bridge_observation_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bridge_version",
            "recorded_bridge_version",
            "row_number",
            "recorded_at",
            "adapter_name",
            "event_ref",
            "operation",
            "source_authority",
            "target_namespace",
            "level",
            "highest_disposition",
            "finding_count",
            "contradiction_count",
            "risk_categories",
            "detector_names",
        ],
        "properties": {
            "bridge_version": {"const": ADAPTER_BRIDGE_VERSION},
            "recorded_bridge_version": {"type": "string", "minLength": 1},
            "row_number": {"type": "integer", "minimum": 1},
            "recorded_at": {
                "anyOf": [
                    {
                        "type": "string",
                        "format": "date-time",
                        "pattern": RFC3339_TIMESTAMP_PATTERN,
                    },
                    {"const": "unavailable-recorded-at"},
                ],
            },
            "adapter_name": {"type": "string", "minLength": 1},
            "event_ref": {
                "type": "string",
                "pattern": r"^adapter-observation-row-[1-9][0-9]*$",
            },
            "operation": {"type": "string", "enum": _enum_values(MemoryOperation)},
            "source_authority": {
                "type": "string",
                "enum": _enum_values(SourceAuthority),
            },
            "target_namespace": {"type": "string", "minLength": 1},
            "level": {"type": "string", "enum": _enum_values(ScanEventLevel)},
            "highest_disposition": {
                "type": "string",
                "enum": _enum_values(RecommendedDisposition),
            },
            "finding_count": {"type": "integer", "minimum": 0},
            "contradiction_count": {"type": "integer", "minimum": 0},
            "risk_categories": {
                "type": "array",
                "items": {"type": "string", "enum": _enum_values(RiskCategory)},
            },
            "detector_names": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
        },
    }


def adapter_bridge_observe_result_schema() -> dict[str, Any]:
    """Return the generic adapter observe-memory result JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-observe-result.mf-23.json",
        "title": "AdapterBridgeObserveResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bridge_version",
            "state_dir",
            "observation",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ],
        "properties": {
            "bridge_version": {"const": ADAPTER_BRIDGE_VERSION},
            "state_dir": {"type": "string", "minLength": 1},
            "observation": _adapter_bridge_observation_summary_schema(),
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
        },
    }


def adapter_bridge_observations_schema() -> dict[str, Any]:
    """Return the redacted generic adapter observations list JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-observations.mf-23.json",
        "title": "AdapterBridgeObservations",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bridge_version",
            "state_dir",
            "limit",
            "total_observations",
            "high_risk_observations",
            "warn_observations",
            "pass_observations",
            "returned_observations",
            "observations",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ],
        "properties": {
            "bridge_version": {"const": ADAPTER_BRIDGE_VERSION},
            "state_dir": {"type": "string", "minLength": 1},
            "limit": {"type": "integer", "minimum": 1},
            "total_observations": {"type": "integer", "minimum": 0},
            "high_risk_observations": {"type": "integer", "minimum": 0},
            "warn_observations": {"type": "integer", "minimum": 0},
            "pass_observations": {"type": "integer", "minimum": 0},
            "returned_observations": {"type": "integer", "minimum": 0},
            "observations": {
                "type": "array",
                "items": _adapter_bridge_observation_summary_schema(),
            },
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
        },
    }


def adapter_bridge_write_through_result_schema() -> dict[str, Any]:
    """Return the generic adapter write-through helper result JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-write-through-result.mf-23.json",
        "title": "AdapterBridgeWriteThroughResult",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bridge_version",
            "state_dir",
            "observation",
            "writer_label",
            "writer_called",
            "writer_succeeded",
            "writer_error_type",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
            "writer_result_included",
        ],
        "properties": {
            "bridge_version": {"const": ADAPTER_BRIDGE_VERSION},
            "state_dir": {"type": "string", "minLength": 1},
            "observation": _adapter_bridge_observation_summary_schema(),
            "writer_label": {"type": "string", "minLength": 1},
            "writer_called": {"type": "boolean"},
            "writer_succeeded": {"type": "boolean"},
            "writer_error_type": {
                "anyOf": [
                    {"type": "string", "minLength": 1},
                    {"type": "null"},
                ],
            },
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
            "writer_result_included": {"const": False},
        },
        "allOf": [
            {
                "if": {"properties": {"writer_called": {"const": False}}},
                "then": {
                    "properties": {
                        "writer_succeeded": {"const": False},
                        "writer_error_type": {"type": "null"},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "writer_called": {"const": True},
                        "writer_succeeded": {"const": False},
                    }
                },
                "then": {
                    "properties": {
                        "writer_error_type": {"type": "string", "minLength": 1}
                    }
                },
            },
            {
                "if": {"properties": {"writer_succeeded": {"const": True}}},
                "then": {"properties": {"writer_error_type": {"type": "null"}}},
            },
        ],
    }


def _adapter_bridge_report_setup_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "overall_status",
            "state_dir_exists",
            "events_file_exists",
            "observations_file_exists",
            "state_dir_mode",
            "events_file_mode",
            "observations_file_mode",
        ],
        "properties": {
            "overall_status": {
                "type": "string",
                "enum": ["ready", "empty", "attention"],
            },
            "state_dir_exists": {"type": "boolean"},
            "events_file_exists": {"type": "boolean"},
            "observations_file_exists": {"type": "boolean"},
            "state_dir_mode": _nullable_octal_mode_schema(),
            "events_file_mode": _nullable_octal_mode_schema(),
            "observations_file_mode": _nullable_octal_mode_schema(),
        },
    }


def _adapter_bridge_report_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "total_observations",
            "pass_observations",
            "warn_observations",
            "high_risk_observations",
            "returned_observations",
            "report_contains_raw_content",
            "hosted_dashboard",
            "production_enforcement",
        ],
        "properties": {
            "total_observations": {"type": "integer", "minimum": 0},
            "pass_observations": {"type": "integer", "minimum": 0},
            "warn_observations": {"type": "integer", "minimum": 0},
            "high_risk_observations": {"type": "integer", "minimum": 0},
            "returned_observations": {"type": "integer", "minimum": 0},
            "report_contains_raw_content": {"const": False},
            "hosted_dashboard": {"const": False},
            "production_enforcement": {"const": False},
        },
    }


def adapter_bridge_report_schema() -> dict[str, Any]:
    """Return the generic adapter local diagnostics report JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/adapter-report.mf-23.json",
        "title": "AdapterBridgeReport",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "report_version",
            "bridge_version",
            "package_version",
            "title",
            "generated_at",
            "state_dir",
            "setup",
            "summary",
            "observations",
            "level_counts",
            "risk_category_counts",
            "detector_counts",
            "next_steps",
            "limitations",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ],
        "properties": {
            "report_version": {"const": ADAPTER_BRIDGE_REPORT_VERSION},
            "bridge_version": {"const": ADAPTER_BRIDGE_VERSION},
            "package_version": {"type": "string", "minLength": 1},
            "title": {"type": "string", "minLength": 1},
            "generated_at": {
                "type": "string",
                "format": "date-time",
                "pattern": RFC3339_TIMESTAMP_PATTERN,
            },
            "state_dir": {"type": "string", "minLength": 1},
            "setup": _adapter_bridge_report_setup_schema(),
            "summary": _adapter_bridge_report_summary_schema(),
            "observations": adapter_bridge_observations_schema(),
            "level_counts": _string_int_count_map_schema(),
            "risk_category_counts": _string_int_count_map_schema(),
            "detector_counts": _string_int_count_map_schema(),
            "next_steps": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
        },
    }


def _hermes_checkup_check_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "status", "message"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "status": {"type": "string", "enum": ["pass", "warn", "fail"]},
            "message": {"type": "string", "minLength": 1},
        },
    }


def _nullable_octal_mode_schema() -> dict[str, Any]:
    return {
        "anyOf": [
            {"type": "string", "pattern": "^[0-7]{4}$"},
            {"type": "null"},
        ],
    }


def hermes_checkup_schema() -> dict[str, Any]:
    """Return the Hermes local setup checkup JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/hermes-checkup.mf-20.json",
        "title": "HermesCheckup",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "integration_version",
            "package_version",
            "overall_status",
            "hermes_home",
            "plugin_name",
            "plugin_dir",
            "manifest_path",
            "init_path",
            "config_path",
            "plugin_shim_installed",
            "manifest_matches",
            "init_matches",
            "config_mentions_plugin",
            "state_dir",
            "state_dir_exists",
            "state_dir_mode",
            "events_file_exists",
            "events_file_mode",
            "observations_file_exists",
            "observations_file_mode",
            "sample_written",
            "checks",
            "next_steps",
            "status",
            "recent_observations",
            "observe_only",
            "production_enforcement",
        ],
        "properties": {
            "integration_version": {"const": HERMES_INTEGRATION_VERSION},
            "package_version": {"type": "string", "minLength": 1},
            "overall_status": {
                "type": "string",
                "enum": ["ready", "needs_setup", "attention"],
            },
            "hermes_home": {"type": "string", "minLength": 1},
            "plugin_name": {"const": "memory-firewall"},
            "plugin_dir": {"type": "string", "minLength": 1},
            "manifest_path": {"type": "string", "minLength": 1},
            "init_path": {"type": "string", "minLength": 1},
            "config_path": {"type": "string", "minLength": 1},
            "plugin_shim_installed": {"type": "boolean"},
            "manifest_matches": {"type": "boolean"},
            "init_matches": {"type": "boolean"},
            "config_mentions_plugin": {"type": "boolean"},
            "state_dir": {"type": "string", "minLength": 1},
            "state_dir_exists": {"type": "boolean"},
            "state_dir_mode": _nullable_octal_mode_schema(),
            "events_file_exists": {"type": "boolean"},
            "events_file_mode": _nullable_octal_mode_schema(),
            "observations_file_exists": {"type": "boolean"},
            "observations_file_mode": _nullable_octal_mode_schema(),
            "sample_written": {"type": "boolean"},
            "checks": {
                "type": "array",
                "minItems": 1,
                "items": _hermes_checkup_check_schema(),
            },
            "next_steps": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "status": hermes_status_schema(),
            "recent_observations": hermes_observations_schema(),
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
        },
    }


def _hermes_report_setup_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "overall_status",
            "plugin_shim_installed",
            "manifest_matches",
            "init_matches",
            "config_mentions_plugin",
            "state_dir_mode",
            "events_file_mode",
            "observations_file_mode",
            "sample_written",
        ],
        "properties": {
            "overall_status": {
                "type": "string",
                "enum": ["ready", "needs_setup", "attention"],
            },
            "plugin_shim_installed": {"type": "boolean"},
            "manifest_matches": {"type": "boolean"},
            "init_matches": {"type": "boolean"},
            "config_mentions_plugin": {"type": "boolean"},
            "state_dir_mode": _nullable_octal_mode_schema(),
            "events_file_mode": _nullable_octal_mode_schema(),
            "observations_file_mode": _nullable_octal_mode_schema(),
            "sample_written": {"type": "boolean"},
        },
    }


def _hermes_report_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "observation_scope",
            "total_observations",
            "current_version_observations",
            "legacy_version_observations",
            "pass_observations",
            "warn_observations",
            "high_risk_observations",
            "blocked_by_firewall",
            "matching_observations",
            "matching_high_risk_observations",
            "matching_warn_observations",
            "matching_pass_observations",
            "returned_observations",
            "report_contains_raw_content",
            "hosted_dashboard",
            "production_enforcement",
        ],
        "properties": {
            "observation_scope": {
                "type": "string",
                "enum": [
                    HERMES_OBSERVATION_SCOPE_ALL,
                    HERMES_OBSERVATION_SCOPE_CURRENT_VERSION,
                ],
            },
            "total_observations": {"type": "integer", "minimum": 0},
            "current_version_observations": {"type": "integer", "minimum": 0},
            "legacy_version_observations": {"type": "integer", "minimum": 0},
            "pass_observations": {"type": "integer", "minimum": 0},
            "warn_observations": {"type": "integer", "minimum": 0},
            "high_risk_observations": {"type": "integer", "minimum": 0},
            "blocked_by_firewall": {"type": "integer", "minimum": 0},
            "matching_observations": {"type": "integer", "minimum": 0},
            "matching_high_risk_observations": {"type": "integer", "minimum": 0},
            "matching_warn_observations": {"type": "integer", "minimum": 0},
            "matching_pass_observations": {"type": "integer", "minimum": 0},
            "returned_observations": {"type": "integer", "minimum": 0},
            "report_contains_raw_content": {"const": False},
            "hosted_dashboard": {"const": False},
            "production_enforcement": {"const": False},
        },
    }


def _string_int_count_map_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "propertyNames": {"type": "string", "minLength": 1},
        "additionalProperties": {"type": "integer", "minimum": 0},
    }


def hermes_report_schema() -> dict[str, Any]:
    """Return the Hermes local diagnostics report JSON schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/eoniclife/memory-firewall/schemas/hermes-report.mf-20.json",
        "title": "HermesReport",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "report_version",
            "integration_version",
            "package_version",
            "title",
            "generated_at",
            "hermes_home",
            "state_dir",
            "setup",
            "summary",
            "status",
            "observations",
            "level_counts",
            "risk_category_counts",
            "detector_counts",
            "next_steps",
            "limitations",
            "observe_only",
            "production_enforcement",
            "raw_content_included",
        ],
        "properties": {
            "report_version": {"const": HERMES_REPORT_VERSION},
            "integration_version": {"const": HERMES_INTEGRATION_VERSION},
            "package_version": {"type": "string", "minLength": 1},
            "title": {"type": "string", "minLength": 1},
            "generated_at": {
                "type": "string",
                "format": "date-time",
                "pattern": RFC3339_TIMESTAMP_PATTERN,
            },
            "hermes_home": {"type": "string", "minLength": 1},
            "state_dir": {"type": "string", "minLength": 1},
            "setup": _hermes_report_setup_schema(),
            "summary": _hermes_report_summary_schema(),
            "status": hermes_status_schema(),
            "observations": hermes_observations_schema(),
            "level_counts": _string_int_count_map_schema(),
            "risk_category_counts": _string_int_count_map_schema(),
            "detector_counts": _string_int_count_map_schema(),
            "next_steps": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "observe_only": {"const": True},
            "production_enforcement": {"const": False},
            "raw_content_included": {"const": False},
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
        "review_queue_schema": review_queue_schema(),
        "override_receipt_schema": override_receipt_schema(),
        "trusted_read_preview_schema": trusted_read_preview_schema(),
        "demo_result_schema": demo_result_schema(),
        "reference_proxy_result_schema": reference_proxy_result_schema(),
        "report_result_schema": report_result_schema(),
        "redacted_report_export_schema": redacted_report_export_schema(),
        "adapter_bridge_observe_result_schema": adapter_bridge_observe_result_schema(),
        "adapter_bridge_observations_schema": adapter_bridge_observations_schema(),
        "adapter_bridge_write_through_result_schema": (
            adapter_bridge_write_through_result_schema()
        ),
        "adapter_bridge_report_schema": adapter_bridge_report_schema(),
        "hermes_checkup_schema": hermes_checkup_schema(),
        "hermes_report_schema": hermes_report_schema(),
        "hermes_status_schema": hermes_status_schema(),
        "hermes_observations_schema": hermes_observations_schema(),
        "default_detector_pack": default_detector_pack().to_dict(),
        "risk_taxonomy": [item.to_dict() for item in risk_taxonomy()],
        "claim_budget": claim_budget().to_dict(),
    }
