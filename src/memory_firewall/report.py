"""Local static report and redacted export helpers."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .adapters import AdapterCapabilityReport
from .demo import PoisonDemoResult, run_poison_demo
from .models import JSONScalar, RecommendedDisposition, _coerce_metadata, _require_string
from .proxy import ProxyMode, ReferenceProxyResult, run_reference_proxy
from .scan import ScanEventLevel

REPORT_VERSION = "mf-10"
REDACTED_EXPORT_VERSION = "mf-10"
REPORT_JSON_FILENAME = "report.json"
REPORT_HTML_FILENAME = "index.html"
REDACTED_EXPORT_FILENAME = "redacted-share.json"
_REDACTED_DEMO_OUTCOME_KEYS = frozenset(
    (
        "naive_memory_was_poisoned",
        "benign_memory_passed",
        "firewall_high_risk_events",
        "queued_items",
        "pending_preview_items",
        "rejected_preview_items",
        "override_preview_items",
        "answer_values_redacted",
        "event_ids_redacted",
    )
)
_REDACTED_PROXY_OUTCOME_KEYS = frozenset(
    (
        "mode",
        "high_risk_events",
        "queued_items",
        "trusted_read_preview_items",
        "suppressed_native_write_count",
        "native_record_count",
        "governed_context_record_count",
        "answer_values_redacted",
        "event_ids_redacted",
    )
)
_REDACTED_EVENT_SUMMARY_KEYS = frozenset(
    (
        "event_label",
        "line_number",
        "level",
        "highest_disposition",
        "finding_count",
        "contradiction_count",
        "risk_categories",
        "review_item_present",
        "suppressed_native_write",
    )
)


def _require_bool(value: bool, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be bool")


def _string_tuple(value: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, tuple):
        raise TypeError(f"{field_name} must be a tuple of strings")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return value


def _json_mapping(value: Mapping[str, Any], field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    json.dumps(value, allow_nan=False, sort_keys=True)
    return dict(value)


def _json_mapping_with_exact_keys(
    value: Mapping[str, Any],
    field_name: str,
    keys: frozenset[str],
) -> dict[str, Any]:
    payload = _json_mapping(value, field_name)
    actual = set(payload)
    if actual != keys:
        missing = sorted(keys - actual)
        unexpected = sorted(actual - keys)
        detail = []
        if missing:
            detail.append(f"missing: {', '.join(missing)}")
        if unexpected:
            detail.append(f"unexpected: {', '.join(unexpected)}")
        raise ValueError(
            f"{field_name} must match redacted schema ({'; '.join(detail)})"
        )
    return payload


def _require_true(value: Any, field_name: str) -> None:
    _require_bool(value, field_name)
    if value is not True:
        raise ValueError(f"{field_name} must be true")


def _require_false(value: Any, field_name: str) -> None:
    _require_bool(value, field_name)
    if value is not False:
        raise ValueError(f"{field_name} must be false")


def _require_non_empty_tuple(
    value: tuple[Any, ...],
    field_name: str,
) -> tuple[Any, ...]:
    if isinstance(value, str) or not isinstance(value, tuple):
        raise TypeError(f"{field_name} must be a tuple")
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    return value


def _validate_redaction_flags(payload: Mapping[str, Any], field_name: str) -> None:
    for key in ("answer_values_redacted", "event_ids_redacted"):
        _require_true(payload[key], f"{field_name}.{key}")


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Compact counters for the local integrity report."""

    pass_events: int
    warn_events: int
    high_risk_events: int
    queued_items: int
    suppressed_native_writes: int
    redacted_share_default: bool
    hosted_dashboard: bool
    production_adapter_support: bool

    def __post_init__(self) -> None:
        for field_name in (
            "pass_events",
            "warn_events",
            "high_risk_events",
            "queued_items",
            "suppressed_native_writes",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        _require_true(self.redacted_share_default, "redacted_share_default")
        _require_false(self.hosted_dashboard, "hosted_dashboard")
        _require_false(
            self.production_adapter_support,
            "production_adapter_support",
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary."""

        return {
            "pass_events": self.pass_events,
            "warn_events": self.warn_events,
            "high_risk_events": self.high_risk_events,
            "queued_items": self.queued_items,
            "suppressed_native_writes": self.suppressed_native_writes,
            "redacted_share_default": self.redacted_share_default,
            "hosted_dashboard": self.hosted_dashboard,
            "production_adapter_support": self.production_adapter_support,
        }


@dataclass(frozen=True, slots=True)
class ReportEventSummary:
    """One event-level row in the local report."""

    event_label: str
    event_id: str
    line_number: int
    level: ScanEventLevel
    highest_disposition: RecommendedDisposition
    finding_count: int
    contradiction_count: int
    risk_categories: tuple[str, ...]
    review_item_id: str | None
    suppressed_native_write: bool

    def __post_init__(self) -> None:
        _require_string(
            self.event_label,
            "event_label",
            allow_empty=False,
            max_chars=128,
        )
        _require_string(self.event_id, "event_id", allow_empty=False, max_chars=96)
        if self.line_number < 1:
            raise ValueError("line_number must be positive")
        if not isinstance(self.level, ScanEventLevel):
            raise TypeError("level must be a ScanEventLevel")
        if not isinstance(self.highest_disposition, RecommendedDisposition):
            raise TypeError("highest_disposition must be a RecommendedDisposition")
        for field_name in ("finding_count", "contradiction_count"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        object.__setattr__(
            self,
            "risk_categories",
            _string_tuple(self.risk_categories, "risk_categories"),
        )
        if self.review_item_id is not None:
            _require_string(
                self.review_item_id,
                "review_item_id",
                allow_empty=False,
                max_chars=96,
            )
        _require_bool(self.suppressed_native_write, "suppressed_native_write")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable event summary."""

        return {
            "event_label": self.event_label,
            "event_id": self.event_id,
            "line_number": self.line_number,
            "level": self.level.value,
            "highest_disposition": self.highest_disposition.value,
            "finding_count": self.finding_count,
            "contradiction_count": self.contradiction_count,
            "risk_categories": list(self.risk_categories),
            "review_item_id": self.review_item_id,
            "suppressed_native_write": self.suppressed_native_write,
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        """Return a share-safe version without stable raw-derived IDs."""

        return {
            "event_label": self.event_label,
            "line_number": self.line_number,
            "level": self.level.value,
            "highest_disposition": self.highest_disposition.value,
            "finding_count": self.finding_count,
            "contradiction_count": self.contradiction_count,
            "risk_categories": list(self.risk_categories),
            "review_item_present": self.review_item_id is not None,
            "suppressed_native_write": self.suppressed_native_write,
        }


@dataclass(frozen=True, slots=True)
class RedactedReportExport:
    """Default share artifact with raw-derived values and IDs removed."""

    export_version: str
    title: str
    summary: ReportSummary
    demo_outcome: Mapping[str, Any]
    proxy_outcomes: tuple[Mapping[str, Any], ...]
    event_summaries: tuple[Mapping[str, Any], ...]
    omissions: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.export_version != REDACTED_EXPORT_VERSION:
            raise ValueError(f"export_version must be {REDACTED_EXPORT_VERSION}")
        _require_string(self.title, "title", allow_empty=False, max_chars=256)
        if not isinstance(self.summary, ReportSummary):
            raise TypeError("summary must be ReportSummary")
        object.__setattr__(
            self,
            "demo_outcome",
            _json_mapping_with_exact_keys(
                self.demo_outcome,
                "demo_outcome",
                _REDACTED_DEMO_OUTCOME_KEYS,
            ),
        )
        _validate_redaction_flags(self.demo_outcome, "demo_outcome")
        _require_non_empty_tuple(self.proxy_outcomes, "proxy_outcomes")
        object.__setattr__(
            self,
            "proxy_outcomes",
            tuple(
                _json_mapping_with_exact_keys(
                    item,
                    "proxy_outcomes item",
                    _REDACTED_PROXY_OUTCOME_KEYS,
                )
                for item in self.proxy_outcomes
            ),
        )
        for item in self.proxy_outcomes:
            _validate_redaction_flags(item, "proxy_outcomes item")
        _require_non_empty_tuple(self.event_summaries, "event_summaries")
        object.__setattr__(
            self,
            "event_summaries",
            tuple(
                _json_mapping_with_exact_keys(
                    item,
                    "event_summaries item",
                    _REDACTED_EVENT_SUMMARY_KEYS,
                )
                for item in self.event_summaries
            ),
        )
        object.__setattr__(self, "omissions", _string_tuple(self.omissions, "omissions"))
        object.__setattr__(
            self,
            "limitations",
            _string_tuple(self.limitations, "limitations"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable redacted export."""

        return {
            "export_version": self.export_version,
            "redacted": True,
            "title": self.title,
            "summary": self.summary.to_dict(),
            "demo_outcome": dict(self.demo_outcome),
            "proxy_outcomes": [dict(item) for item in self.proxy_outcomes],
            "event_summaries": [dict(item) for item in self.event_summaries],
            "omissions": list(self.omissions),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ReportResult:
    """Local deterministic report over existing demo/proxy surfaces."""

    report_version: str
    title: str
    source: str
    summary: ReportSummary
    demo_outcome: Mapping[str, Any]
    proxy_outcomes: tuple[Mapping[str, Any], ...]
    event_summaries: tuple[ReportEventSummary, ...]
    capability_report: AdapterCapabilityReport
    limitations: tuple[str, ...]
    metadata: Mapping[str, JSONScalar]

    def __post_init__(self) -> None:
        if self.report_version != REPORT_VERSION:
            raise ValueError(f"report_version must be {REPORT_VERSION}")
        _require_string(self.title, "title", allow_empty=False, max_chars=256)
        _require_string(self.source, "source", allow_empty=False, max_chars=256)
        if not isinstance(self.summary, ReportSummary):
            raise TypeError("summary must be ReportSummary")
        object.__setattr__(
            self,
            "demo_outcome",
            _json_mapping(self.demo_outcome, "demo_outcome"),
        )
        object.__setattr__(
            self,
            "proxy_outcomes",
            tuple(
                _json_mapping(item, "proxy_outcomes item")
                for item in self.proxy_outcomes
            ),
        )
        _require_non_empty_tuple(self.proxy_outcomes, "proxy_outcomes")
        if any(not isinstance(item, ReportEventSummary) for item in self.event_summaries):
            raise TypeError("event_summaries must contain ReportEventSummary")
        _require_non_empty_tuple(self.event_summaries, "event_summaries")
        if not isinstance(self.capability_report, AdapterCapabilityReport):
            raise TypeError("capability_report must be AdapterCapabilityReport")
        object.__setattr__(
            self,
            "limitations",
            _string_tuple(self.limitations, "limitations"),
        )
        object.__setattr__(self, "metadata", _coerce_metadata(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report."""

        return {
            "report_version": self.report_version,
            "title": self.title,
            "source": self.source,
            "summary": self.summary.to_dict(),
            "demo_outcome": dict(self.demo_outcome),
            "proxy_outcomes": [dict(item) for item in self.proxy_outcomes],
            "event_summaries": [item.to_dict() for item in self.event_summaries],
            "capability_report": self.capability_report.to_dict(),
            "limitations": list(self.limitations),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReportBundle:
    """Files written for a local report bundle."""

    report: ReportResult
    redacted_export: RedactedReportExport
    output_dir: Path
    report_json_path: Path
    html_path: Path
    redacted_export_path: Path

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable redacted bundle summary."""

        return {
            "report_version": self.report.report_version,
            "title": self.report.title,
            "summary": self.report.summary.to_dict(),
            "redacted_export": self.redacted_export.to_dict(),
            "files": {
                "paths_redacted": True,
                "report_json": self.report_json_path.name,
                "html": self.html_path.name,
                "redacted_export": self.redacted_export_path.name,
            },
        }


def _event_summaries(
    demo: PoisonDemoResult,
    enforce_proxy: ReferenceProxyResult,
) -> tuple[ReportEventSummary, ...]:
    review_item_by_event = {item.event_id: item.item_id for item in demo.review_queue.items}
    suppressed_lines = {
        decision.line_number
        for decision in enforce_proxy.write_decisions
        if not decision.native_write
    }
    summaries: list[ReportEventSummary] = []
    for index, event in enumerate(demo.scan_result.events, start=1):
        categories = tuple(
            sorted(
                {
                    finding.risk_category.value
                    for finding in event.detector_result.findings
                }
            )
        )
        summaries.append(
            ReportEventSummary(
                event_label=f"event_{index}",
                event_id=event.event_id,
                line_number=event.line_number,
                level=event.level,
                highest_disposition=event.highest_disposition,
                finding_count=event.finding_count,
                contradiction_count=event.contradiction_count,
                risk_categories=categories,
                review_item_id=review_item_by_event.get(event.event_id),
                suppressed_native_write=event.line_number in suppressed_lines,
            )
        )
    return tuple(summaries)


def _redacted_demo_outcome(demo_outcome: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "naive_memory_was_poisoned": bool(demo_outcome["naive_memory_was_poisoned"]),
        "benign_memory_passed": bool(demo_outcome["benign_memory_passed"]),
        "firewall_high_risk_events": int(demo_outcome["firewall_high_risk_events"]),
        "queued_items": int(demo_outcome["queued_items"]),
        "pending_preview_items": int(demo_outcome["pending_preview_items"]),
        "rejected_preview_items": int(demo_outcome["rejected_preview_items"]),
        "override_preview_items": int(demo_outcome["override_preview_items"]),
        "answer_values_redacted": True,
        "event_ids_redacted": True,
    }


def _redacted_proxy_outcome(proxy_outcome: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": str(proxy_outcome["mode"]),
        "high_risk_events": int(proxy_outcome["high_risk_events"]),
        "queued_items": int(proxy_outcome["queued_items"]),
        "trusted_read_preview_items": int(proxy_outcome["trusted_read_preview_items"]),
        "suppressed_native_write_count": len(
            proxy_outcome["suppressed_native_event_ids"]
        ),
        "native_record_count": int(proxy_outcome["native_record_count"]),
        "governed_context_record_count": int(
            proxy_outcome["governed_context_record_count"]
        ),
        "answer_values_redacted": True,
        "event_ids_redacted": True,
    }


def redact_report_export(report: ReportResult) -> RedactedReportExport:
    """Build the default share-safe export for a local report."""

    return RedactedReportExport(
        export_version=REDACTED_EXPORT_VERSION,
        title=report.title,
        summary=report.summary,
        demo_outcome=_redacted_demo_outcome(report.demo_outcome),
        proxy_outcomes=tuple(
            _redacted_proxy_outcome(item) for item in report.proxy_outcomes
        ),
        event_summaries=tuple(
            item.to_redacted_dict() for item in report.event_summaries
        ),
        omissions=(
            "raw_or_redacted_content",
            "proposed_memory",
            "event_id",
            "source_id",
            "state object values",
            "review_item_id",
            "receipt_id",
        ),
        limitations=report.limitations,
    )


def generate_demo_report() -> ReportResult:
    """Generate the deterministic local demo/proxy report."""

    demo = run_poison_demo()
    proxies = tuple(run_reference_proxy(mode) for mode in ProxyMode)
    enforce_proxy = next(item for item in proxies if item.mode == ProxyMode.ENFORCE)
    demo_summary = demo.scan_result.summary
    enforce_outcome = enforce_proxy.outcome()
    summary = ReportSummary(
        pass_events=demo_summary.pass_events,
        warn_events=demo_summary.warn_events,
        high_risk_events=demo_summary.high_risk_events,
        queued_items=len(demo.review_queue.items),
        suppressed_native_writes=len(enforce_outcome["suppressed_native_event_ids"]),
        redacted_share_default=True,
        hosted_dashboard=False,
        production_adapter_support=False,
    )
    return ReportResult(
        report_version=REPORT_VERSION,
        title="Memory Firewall Local Integrity Report",
        source="memory-firewall-demo-and-reference-proxy",
        summary=summary,
        demo_outcome=demo.outcome(),
        proxy_outcomes=tuple(item.outcome() for item in proxies),
        event_summaries=_event_summaries(demo, enforce_proxy),
        capability_report=enforce_proxy.capability_report,
        limitations=(
            "Local static report only.",
            "Redacted share export is generated by default.",
            "HTML report is local; no hosted dashboard, auth, billing, or telemetry service is started.",
            "Reference enforce mode applies only to the controlled SQLite reference store.",
            "Reports are integrity signals, not proof of objective truth or universal poisoning detection.",
        ),
        metadata={
            "raw_content_shared_by_default": False,
            "report_contains_full_event_payloads": False,
            "release_execution": "not_performed",
        },
    )


def _render_summary_list(items: Mapping[str, Any]) -> str:
    rows = []
    for key in sorted(items):
        value = items[key]
        rows.append(
            f"<li><span>{html.escape(str(key).replace('_', ' '))}</span>"
            f"<strong>{html.escape(str(value))}</strong></li>"
        )
    return "\n".join(rows)


def render_report_html(report: ReportResult) -> str:
    """Render a self-contained local HTML report."""

    proxy_rows = []
    for outcome in report.proxy_outcomes:
        proxy_rows.append(
            "<tr>"
            f"<td>{html.escape(str(outcome['mode']))}</td>"
            f"<td>{html.escape(str(outcome['native_answer']))}</td>"
            f"<td>{html.escape(str(outcome['governed_context_answer']))}</td>"
            f"<td>{len(outcome['suppressed_native_event_ids'])}</td>"
            "</tr>"
        )
    event_rows = []
    for item in report.event_summaries:
        event_rows.append(
            "<tr>"
            f"<td>{html.escape(item.event_label)}</td>"
            f"<td>{html.escape(item.level.value)}</td>"
            f"<td>{html.escape(item.highest_disposition.value)}</td>"
            f"<td>{item.finding_count}</td>"
            f"<td>{item.contradiction_count}</td>"
            f"<td>{html.escape(', '.join(item.risk_categories) or 'none')}</td>"
            f"<td>{'yes' if item.suppressed_native_write else 'no'}</td>"
            "</tr>"
        )
    limitations = "".join(
        f"<li>{html.escape(item)}</li>" for item in report.limitations
    )
    supported = ", ".join(report.capability_report.to_dict()["supported_capabilities"])
    unsupported = ", ".join(
        report.capability_report.to_dict()["unsupported_capabilities"]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(report.title)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #151515; background: #f7f7f4; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }}
    h1, h2 {{ line-height: 1.15; }}
    .lede {{ font-size: 1.05rem; max-width: 760px; color: #454545; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; padding: 0; list-style: none; }}
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
  <p class="lede">A prompt injection can end while its effect survives inside memory. This local report summarizes the deterministic poisoning demo and the bounded SQLite reference proxy. It does not start a hosted service.</p>
  <h2>Summary</h2>
  <ul class="grid">
    {_render_summary_list(report.summary.to_dict())}
  </ul>
  <h2>Demo Outcome</h2>
  <ul class="grid">
    {_render_summary_list(report.demo_outcome)}
  </ul>
  <h2>Reference Proxy Modes</h2>
  <table>
    <thead><tr><th>Mode</th><th>Native answer</th><th>Governed context answer</th><th>Suppressed writes</th></tr></thead>
    <tbody>{''.join(proxy_rows)}</tbody>
  </table>
  <h2>Event Review</h2>
  <table>
    <thead><tr><th>Event</th><th>Level</th><th>Disposition</th><th>Findings</th><th>Contradictions</th><th>Risk categories</th><th>Suppressed</th></tr></thead>
    <tbody>{''.join(event_rows)}</tbody>
  </table>
  <h2>Capability Boundary</h2>
  <p><strong>Adapter:</strong> <code>{html.escape(report.capability_report.adapter_name)}</code></p>
  <p><strong>Supported capabilities:</strong> {html.escape(supported)}</p>
  <p><strong>Unsupported capabilities:</strong> {html.escape(unsupported)}</p>
  <h2>Limitations</h2>
  <ul>{limitations}</ul>
</main>
</body>
</html>
"""


def write_report_bundle(report: ReportResult, output_dir: str | Path) -> ReportBundle:
    """Write report JSON, local HTML, and redacted share export."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    redacted_export = redact_report_export(report)
    report_json_path = destination / REPORT_JSON_FILENAME
    html_path = destination / REPORT_HTML_FILENAME
    redacted_export_path = destination / REDACTED_EXPORT_FILENAME
    report_json_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    html_path.write_text(render_report_html(report), encoding="utf-8")
    redacted_export_path.write_text(
        json.dumps(redacted_export.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return ReportBundle(
        report=report,
        redacted_export=redacted_export,
        output_dir=destination,
        report_json_path=report_json_path,
        html_path=html_path,
        redacted_export_path=redacted_export_path,
    )
