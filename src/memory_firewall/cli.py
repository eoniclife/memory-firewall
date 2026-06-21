"""Command-line entry point for Memory Firewall."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from .adapters import demo_memory_adapter
from .adapter_bridge import (
    generate_adapter_report,
    observe_memory_candidate,
    recent_adapter_observations,
    write_adapter_report_bundle,
)
from .analysis import MemoryStateAssertion, analyze_memory_state
from .claim_budget import claim_budget
from .conformance import run_adapter_conformance
from .detectors import default_detector_pack, run_detectors
from .demo import run_poison_demo
from .doctor import doctor_report
from .hermes import (
    check_hermes_setup,
    generate_hermes_report,
    install_hermes_plugin_shim,
    recent_hermes_observations,
    summarize_hermes_observations,
    write_hermes_report_bundle,
)
from .lineage import load_lineage_report
from .models import MemoryEvent, MemoryOperation, SourceAuthority, SourceType
from .policy import DISPOSITION_ORDER, SEVERITY_ORDER, PolicyConfig
from .proxy import ProxyMode, run_reference_proxy
from .report import generate_demo_report, write_report_bundle
from .review import (
    ReviewQueue,
    allow_review_item,
    enqueue_scan_result,
    load_review_queue,
    reject_review_item,
    save_review_queue,
    trusted_read_preview,
)
from .scan import (
    SCAN_VERSION,
    exit_code_for_summary,
    scan_jsonl_events,
    watch_stdin_events,
)
from .schema import (
    adapter_bridge_observations_schema,
    adapter_bridge_report_schema,
    adapter_bridge_observe_result_schema,
    adapter_bridge_write_through_result_schema,
    adapter_capability_report_schema,
    detector_pack_schema,
    detector_result_schema,
    demo_result_schema,
    evidence_span_schema,
    event_schema,
    finding_schema,
    hermes_checkup_schema,
    hermes_observations_schema,
    hermes_report_schema,
    hermes_status_schema,
    lineage_report_schema,
    override_receipt_schema,
    policy_schema,
    reference_proxy_result_schema,
    redacted_report_export_schema,
    report_result_schema,
    review_queue_schema,
    scan_result_schema,
    schema_bundle,
    state_analysis_schema,
    state_assertion_schema,
    trusted_read_preview_schema,
)
from .taxonomy import risk_taxonomy
from .version import __version__


def _print_json(payload: Any, stdout: TextIO) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), file=stdout)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memory-firewall",
        description="Local-first integrity checks for persistent agent memory.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local setup.")
    doctor_parser.add_argument("--json", action="store_true", dest="as_json")

    schema_parser = subparsers.add_parser(
        "schema", help="Print machine-readable contract schemas."
    )
    schema_parser.add_argument(
        "name",
        choices=(
            "event",
            "evidence-span",
            "finding",
            "adapter",
            "policy",
            "detector-pack",
            "detector-result",
            "state-assertion",
            "state-analysis",
            "scan-result",
            "review-queue",
            "override-receipt",
            "trusted-read-preview",
            "demo-result",
            "reference-proxy-result",
            "report-result",
            "redacted-report-export",
            "adapter-observe-result",
            "adapter-observations",
            "adapter-write-through-result",
            "adapter-report",
            "hermes-checkup",
            "hermes-report",
            "hermes-status",
            "hermes-observations",
            "lineage-report",
            "bundle",
        ),
        help="Schema to print.",
    )

    risks_parser = subparsers.add_parser("risks", help="Print risk taxonomy.")
    risks_parser.add_argument("--json", action="store_true", dest="as_json")

    claims_parser = subparsers.add_parser("claims", help="Print claim budget.")
    claims_parser.add_argument("--json", action="store_true", dest="as_json")

    policy_parser = subparsers.add_parser(
        "policy", help="Print deterministic policy defaults."
    )
    policy_parser.add_argument("--json", action="store_true", dest="as_json")

    detect_parser = subparsers.add_parser(
        "detect", help="Run built-in deterministic detectors over one event JSON."
    )
    detect_parser.add_argument(
        "--event",
        default="-",
        help="Path to MemoryEvent JSON. Use '-' to read from stdin.",
    )
    detect_parser.add_argument("--json", action="store_true", dest="as_json")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze one event as an AMC candidate/state assertion preview.",
    )
    analyze_parser.add_argument(
        "--event",
        default="-",
        help="Path to MemoryEvent JSON. Use '-' to read from stdin.",
    )
    analyze_parser.add_argument(
        "--existing-assertions",
        help=(
            "Optional path to a JSON array of MemoryStateAssertion records to "
            "check for contradictions."
        ),
    )
    analyze_parser.add_argument("--json", action="store_true", dest="as_json")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a JSONL file of MemoryEvent records.",
    )
    scan_parser.add_argument(
        "path",
        help="Path to a line-delimited MemoryEvent JSON file.",
    )
    scan_parser.add_argument(
        "--existing-assertions",
        help=(
            "Optional path to a JSON array of MemoryStateAssertion records to "
            "seed scan-local contradiction checks."
        ),
    )
    scan_parser.add_argument("--json", action="store_true", dest="as_json")
    scan_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Omit per-event records from JSON output and terminal output.",
    )

    watch_parser = subparsers.add_parser(
        "watch",
        help="Watch normalized MemoryEvent JSONL from stdin.",
    )
    watch_parser.add_argument(
        "--stdin",
        action="store_true",
        required=True,
        help="Read MemoryEvent JSONL from stdin. No live adapters are started.",
    )
    watch_parser.add_argument(
        "--existing-assertions",
        help=(
            "Optional path to a JSON array of MemoryStateAssertion records to "
            "seed watch-local contradiction checks."
        ),
    )
    watch_parser.add_argument("--json", action="store_true", dest="as_json")

    review_parser = subparsers.add_parser(
        "review",
        help="Manage a local review queue for high-risk scan events.",
    )
    review_subparsers = review_parser.add_subparsers(
        dest="review_command",
        required=True,
    )

    review_enqueue_parser = review_subparsers.add_parser(
        "enqueue",
        help="Scan a MemoryEvent JSONL file and enqueue high-risk events.",
    )
    review_enqueue_parser.add_argument(
        "path",
        help="Path to a line-delimited MemoryEvent JSON file.",
    )
    review_enqueue_parser.add_argument(
        "--queue",
        required=True,
        help="Path to the local review queue JSON file.",
    )
    review_enqueue_parser.add_argument(
        "--existing-assertions",
        help=(
            "Optional path to a JSON array of MemoryStateAssertion records to "
            "seed scan-local contradiction checks."
        ),
    )
    review_enqueue_parser.add_argument("--json", action="store_true", dest="as_json")

    review_list_parser = review_subparsers.add_parser(
        "list",
        help="List local review queue items.",
    )
    review_list_parser.add_argument(
        "--queue",
        required=True,
        help="Path to the local review queue JSON file.",
    )
    review_list_parser.add_argument("--json", action="store_true", dest="as_json")

    for command_name in ("allow", "reject"):
        decision_parser = review_subparsers.add_parser(
            command_name,
            help=f"{command_name.title()} one local review item.",
        )
        decision_parser.add_argument(
            "--queue",
            required=True,
            help="Path to the local review queue JSON file.",
        )
        decision_parser.add_argument(
            "--item-id",
            required=True,
            help="Review item id to decide.",
        )
        decision_parser.add_argument(
            "--reason",
            required=True,
            help="Non-empty reason for the local override decision.",
        )
        decision_parser.add_argument(
            "--reviewer",
            default="local-reviewer",
            help="Reviewer label for the local override receipt.",
        )
        decision_parser.add_argument("--json", action="store_true", dest="as_json")

    review_preview_parser = review_subparsers.add_parser(
        "trusted-read-preview",
        help="Print a local preview over allowed review items.",
    )
    review_preview_parser.add_argument(
        "--queue",
        required=True,
        help="Path to the local review queue JSON file.",
    )
    review_preview_parser.add_argument("--json", action="store_true", dest="as_json")

    conformance_parser = subparsers.add_parser(
        "conformance", help="Run adapter conformance probes."
    )
    conformance_parser.add_argument(
        "adapter",
        choices=("demo",),
        help="Adapter probe to run. This package ships only the built-in demo adapter.",
    )
    conformance_parser.add_argument("--json", action="store_true", dest="as_json")

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run deterministic local demos.",
    )
    demo_subparsers = demo_parser.add_subparsers(
        dest="demo_command",
        required=True,
    )
    poison_parser = demo_subparsers.add_parser(
        "poison",
        help="Show a local memory-poisoning failure and review path.",
    )
    poison_parser.add_argument("--json", action="store_true", dest="as_json")

    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Run bounded local reference proxy flows.",
    )
    proxy_subparsers = proxy_parser.add_subparsers(
        dest="proxy_command",
        required=True,
    )
    reference_parser = proxy_subparsers.add_parser(
        "reference",
        help="Run the custom SQLite reference proxy demo.",
    )
    reference_parser.add_argument(
        "--mode",
        choices=tuple(mode.value for mode in ProxyMode),
        default=ProxyMode.OBSERVE.value,
        help="Reference proxy mode to run.",
    )
    reference_parser.add_argument("--json", action="store_true", dest="as_json")

    report_parser = subparsers.add_parser(
        "report",
        help="Generate local static reports.",
    )
    report_subparsers = report_parser.add_subparsers(
        dest="report_command",
        required=True,
    )
    report_demo_parser = report_subparsers.add_parser(
        "demo",
        help="Write the deterministic demo report bundle.",
    )
    report_demo_parser.add_argument(
        "--out",
        required=True,
        help="Directory for report.json, index.html, and redacted-share.json.",
    )
    report_demo_parser.add_argument("--json", action="store_true", dest="as_json")

    adapter_parser = subparsers.add_parser(
        "adapter",
        help="Observe one generic local memory candidate.",
    )
    adapter_subparsers = adapter_parser.add_subparsers(
        dest="adapter_command",
        required=True,
    )
    adapter_observe_parser = adapter_subparsers.add_parser(
        "observe-memory",
        help="Normalize, scan, and persist one supplied memory candidate.",
    )
    content_source = adapter_observe_parser.add_mutually_exclusive_group(required=True)
    content_source.add_argument(
        "--content",
        help="Candidate memory content supplied by the calling agent.",
    )
    content_source.add_argument(
        "--content-file",
        help="File containing candidate memory content supplied by the calling agent.",
    )
    adapter_observe_parser.add_argument(
        "--target",
        default="memory",
        help="Target namespace label for this candidate.",
    )
    adapter_observe_parser.add_argument(
        "--actor",
        default="agent:local",
        help="Actor label for this candidate.",
    )
    adapter_observe_parser.add_argument(
        "--scope",
        default="local",
        help="User or tenant scope label for this candidate.",
    )
    adapter_observe_parser.add_argument(
        "--source-type",
        choices=tuple(item.value for item in SourceType),
        default=SourceType.UNKNOWN.value,
        help="Source type for the candidate.",
    )
    adapter_observe_parser.add_argument(
        "--source-id",
        default="adapter-bridge",
        help="Source id for the candidate.",
    )
    adapter_observe_parser.add_argument(
        "--source-authority",
        choices=tuple(item.value for item in SourceAuthority),
        default=SourceAuthority.UNTRUSTED.value,
        help="Source authority for the candidate.",
    )
    adapter_observe_parser.add_argument(
        "--operation",
        choices=tuple(item.value for item in MemoryOperation),
        default=MemoryOperation.CREATE.value,
        help="Memory operation requested by the calling agent.",
    )
    adapter_observe_parser.add_argument(
        "--adapter-name",
        default="local-adapter",
        help="Local adapter label to store with the observation.",
    )
    adapter_observe_parser.add_argument(
        "--state-dir",
        help="Directory for local private generic adapter diagnostics.",
    )
    adapter_observe_parser.add_argument("--json", action="store_true", dest="as_json")
    adapter_observations_parser = adapter_subparsers.add_parser(
        "observations",
        help="Show recent redacted generic adapter observations.",
    )
    adapter_observations_parser.add_argument(
        "--state-dir",
        help="Directory containing local generic adapter diagnostics.",
    )
    adapter_observations_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=20,
        help="Maximum number of recent observations to show.",
    )
    adapter_observations_parser.add_argument("--json", action="store_true", dest="as_json")
    adapter_report_parser = adapter_subparsers.add_parser(
        "report",
        help="Write a local redacted report over generic adapter diagnostics.",
    )
    adapter_report_parser.add_argument(
        "--state-dir",
        help="Directory containing local generic adapter diagnostics.",
    )
    adapter_report_parser.add_argument(
        "--out",
        required=True,
        help="Directory for report.json, index.html, and redacted-share.json.",
    )
    adapter_report_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=50,
        help="Maximum number of recent observations to include.",
    )
    adapter_report_parser.add_argument(
        "--open",
        action="store_true",
        dest="open_report",
        help="Open the generated local HTML report in the default browser.",
    )
    adapter_report_parser.add_argument("--json", action="store_true", dest="as_json")

    hermes_parser = subparsers.add_parser(
        "hermes",
        help="Inspect the observe-only Hermes hook integration.",
    )
    hermes_subparsers = hermes_parser.add_subparsers(
        dest="hermes_command",
        required=True,
    )
    hermes_status_parser = hermes_subparsers.add_parser(
        "status",
        help="Summarize local Hermes Memory Firewall observations.",
    )
    hermes_status_parser.add_argument(
        "--state-dir",
        help="Directory containing Hermes Memory Firewall JSONL diagnostics.",
    )
    hermes_status_parser.add_argument("--json", action="store_true", dest="as_json")
    hermes_observations_parser = hermes_subparsers.add_parser(
        "observations",
        help="Show recent redacted Hermes Memory Firewall observations.",
    )
    hermes_observations_parser.add_argument(
        "--state-dir",
        help="Directory containing Hermes Memory Firewall JSONL diagnostics.",
    )
    hermes_observations_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=20,
        help="Maximum number of recent observations to show.",
    )
    hermes_observations_parser.add_argument(
        "--current-version-only",
        action="store_true",
        help="Show only rows recorded by the current Hermes adapter version.",
    )
    hermes_observations_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )
    hermes_checkup_parser = hermes_subparsers.add_parser(
        "checkup",
        help="Verify the local Hermes adapter setup and diagnostics path.",
    )
    hermes_checkup_parser.add_argument(
        "--hermes-home",
        help="Hermes home directory. Defaults to HERMES_HOME or ~/.hermes.",
    )
    hermes_checkup_parser.add_argument(
        "--state-dir",
        help="Directory containing Hermes Memory Firewall JSONL diagnostics.",
    )
    hermes_checkup_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=5,
        help="Maximum number of recent observations to include.",
    )
    hermes_checkup_parser.add_argument(
        "--write-sample",
        action="store_true",
        help="Write one synthetic local observation to prove the readout path.",
    )
    hermes_checkup_parser.add_argument("--json", action="store_true", dest="as_json")
    hermes_report_parser = hermes_subparsers.add_parser(
        "report",
        help="Write a local redacted report over Hermes Memory Firewall diagnostics.",
    )
    hermes_report_parser.add_argument(
        "--hermes-home",
        help="Hermes home directory. Defaults to HERMES_HOME or ~/.hermes.",
    )
    hermes_report_parser.add_argument(
        "--state-dir",
        help="Directory containing Hermes Memory Firewall JSONL diagnostics.",
    )
    hermes_report_parser.add_argument(
        "--out",
        required=True,
        help="Directory for report.json, index.html, and redacted-share.json.",
    )
    hermes_report_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=50,
        help="Maximum number of recent observations to include.",
    )
    hermes_report_parser.add_argument(
        "--write-sample",
        action="store_true",
        help="Write one synthetic local observation before generating the report.",
    )
    hermes_report_parser.add_argument(
        "--current-version-only",
        action="store_true",
        help="Report only rows recorded by the current Hermes adapter version.",
    )
    hermes_report_parser.add_argument(
        "--open",
        action="store_true",
        dest="open_report",
        help="Open the generated local HTML report in the default browser.",
    )
    hermes_report_parser.add_argument("--json", action="store_true", dest="as_json")
    hermes_install_parser = hermes_subparsers.add_parser(
        "install-plugin",
        help="Install the Hermes user-plugin shim for current Hermes CLI discovery.",
    )
    hermes_install_parser.add_argument(
        "--hermes-home",
        help="Hermes home directory. Defaults to HERMES_HOME or ~/.hermes.",
    )
    hermes_install_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing memory-firewall user-plugin shim.",
    )
    hermes_install_parser.add_argument("--json", action="store_true", dest="as_json")

    lineage_parser = subparsers.add_parser(
        "lineage",
        help="Inspect stage-aware memory candidate lineage packets.",
    )
    lineage_subparsers = lineage_parser.add_subparsers(
        dest="lineage_command",
        required=True,
    )
    lineage_report_parser = lineage_subparsers.add_parser(
        "report",
        help="Generate a candidate-level lineage report from one JSON packet.",
    )
    lineage_report_parser.add_argument(
        "path",
        help="Path to a stage-aware lineage input JSON file.",
    )
    lineage_report_parser.add_argument("--json", action="store_true", dest="as_json")

    return parser


def _run_doctor(as_json: bool, stdout: TextIO) -> int:
    report = doctor_report()
    if as_json:
        _print_json(report.to_dict(), stdout)
    else:
        status = "ok" if report.ok else "needs attention"
        print(f"memory-firewall {report.version}: {status}", file=stdout)
        for warning in report.warnings:
            print(f"- {warning}", file=stdout)
    return 0 if report.ok else 1


def _run_schema(name: str, stdout: TextIO) -> int:
    if name == "event":
        payload = event_schema()
    elif name == "evidence-span":
        payload = evidence_span_schema()
    elif name == "finding":
        payload = finding_schema()
    elif name == "adapter":
        payload = adapter_capability_report_schema()
    elif name == "policy":
        payload = policy_schema()
    elif name == "detector-pack":
        payload = detector_pack_schema()
    elif name == "detector-result":
        payload = detector_result_schema()
    elif name == "state-assertion":
        payload = state_assertion_schema()
    elif name == "state-analysis":
        payload = state_analysis_schema()
    elif name == "scan-result":
        payload = scan_result_schema()
    elif name == "review-queue":
        payload = review_queue_schema()
    elif name == "override-receipt":
        payload = override_receipt_schema()
    elif name == "trusted-read-preview":
        payload = trusted_read_preview_schema()
    elif name == "demo-result":
        payload = demo_result_schema()
    elif name == "reference-proxy-result":
        payload = reference_proxy_result_schema()
    elif name == "report-result":
        payload = report_result_schema()
    elif name == "redacted-report-export":
        payload = redacted_report_export_schema()
    elif name == "adapter-observe-result":
        payload = adapter_bridge_observe_result_schema()
    elif name == "adapter-observations":
        payload = adapter_bridge_observations_schema()
    elif name == "adapter-write-through-result":
        payload = adapter_bridge_write_through_result_schema()
    elif name == "adapter-report":
        payload = adapter_bridge_report_schema()
    elif name == "hermes-checkup":
        payload = hermes_checkup_schema()
    elif name == "hermes-report":
        payload = hermes_report_schema()
    elif name == "hermes-status":
        payload = hermes_status_schema()
    elif name == "hermes-observations":
        payload = hermes_observations_schema()
    elif name == "lineage-report":
        payload = lineage_report_schema()
    else:
        payload = schema_bundle()
    _print_json(payload, stdout)
    return 0


def _run_risks(as_json: bool, stdout: TextIO) -> int:
    payload = [item.to_dict() for item in risk_taxonomy()]
    if as_json:
        _print_json(payload, stdout)
    else:
        for item in risk_taxonomy():
            print(f"{item.key.value}: {item.question}", file=stdout)
    return 0


def _run_claims(as_json: bool, stdout: TextIO) -> int:
    payload = claim_budget()
    if as_json:
        _print_json(payload.to_dict(), stdout)
    else:
        print("Allowed claims:", file=stdout)
        for claim in payload.allowed:
            print(f"- {claim}", file=stdout)
        print("Non-claims:", file=stdout)
        for claim in payload.not_allowed:
            print(f"- {claim}", file=stdout)
    return 0


def _policy_defaults_payload() -> dict[str, Any]:
    severity_order = [
        severity.value
        for severity, _rank in sorted(SEVERITY_ORDER.items(), key=lambda item: item[1])
    ]
    disposition_order = [
        disposition.value
        for disposition, _rank in sorted(
            DISPOSITION_ORDER.items(), key=lambda item: item[1]
        )
    ]
    return {
        "policy_version": "mf-03",
        "severity_order": severity_order,
        "disposition_order": disposition_order,
        "default_config": PolicyConfig().to_dict(),
    }


def _run_policy(as_json: bool, stdout: TextIO) -> int:
    payload = _policy_defaults_payload()
    if as_json:
        _print_json(payload, stdout)
    else:
        print(f"Policy version: {payload['policy_version']}", file=stdout)
        print("Severity order:", file=stdout)
        for severity in payload["severity_order"]:
            print(f"- {severity}", file=stdout)
        print("Disposition order:", file=stdout)
        for disposition in payload["disposition_order"]:
            print(f"- {disposition}", file=stdout)
    return 0


def _load_event_json(event_path: str, stdin: TextIO) -> dict[str, Any]:
    if event_path == "-":
        raw = stdin.read()
    else:
        raw = Path(event_path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise TypeError("event JSON must be an object")
    return payload


def _run_detect(event_path: str, as_json: bool, stdin: TextIO, stdout: TextIO) -> int:
    event = MemoryEvent.from_dict(_load_event_json(event_path, stdin))
    result = run_detectors(event)
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(
            f"{default_detector_pack().name} {default_detector_pack().version}: "
            f"{len(result.findings)} finding(s)",
            file=stdout,
        )
        for finding in result.findings:
            print(
                f"- {finding.risk_category.value}: "
                f"{finding.recommended_disposition.value}: "
                f"{finding.explanation}",
                file=stdout,
            )
    return 0


def _load_existing_assertions(path: str | None) -> tuple[MemoryStateAssertion, ...]:
    if path is None:
        return ()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise TypeError("existing assertions JSON must be an array")
    return tuple(MemoryStateAssertion.from_dict(item) for item in payload)


def _run_analyze(
    event_path: str,
    existing_assertions_path: str | None,
    as_json: bool,
    stdin: TextIO,
    stdout: TextIO,
) -> int:
    event = MemoryEvent.from_dict(_load_event_json(event_path, stdin))
    result = analyze_memory_state(
        event,
        existing_assertions=_load_existing_assertions(existing_assertions_path),
    )
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(
            f"{result.analysis_version}: {result.trusted_state_action.value}",
            file=stdout,
        )
        for reason in result.reason_codes:
            print(f"- {reason}", file=stdout)
    return 0


def _run_scan(
    path: str,
    existing_assertions_path: str | None,
    as_json: bool,
    summary_only: bool,
    stdout: TextIO,
) -> int:
    with Path(path).open("r", encoding="utf-8") as handle:
        result = scan_jsonl_events(
            handle,
            source=path,
            existing_assertions=_load_existing_assertions(existing_assertions_path),
            include_events=not summary_only,
        )
    if as_json:
        _print_json(result.to_dict(include_events=not summary_only), stdout)
    else:
        summary = result.summary
        print(
            f"{SCAN_VERSION}: {result.source}: "
            f"{summary.analyzed_events}/{summary.total_lines} event(s), "
            f"{summary.invalid_lines} invalid, "
            f"{summary.high_risk_events} high-risk",
            file=stdout,
        )
        if not summary_only:
            for issue in result.issues:
                print(
                    f"- INVALID line={issue.line_number} issue={issue.issue_id}",
                    file=stdout,
                )
            for event in result.events:
                level = event.level.value.replace("_", "-").upper()
                print(
                    f"- {level} line={event.line_number} "
                    f"event={event.event_id} findings={event.finding_count} "
                    f"disposition={event.highest_disposition.value}",
                    file=stdout,
                )
    return exit_code_for_summary(result.summary)


def _run_watch(
    existing_assertions_path: str | None,
    as_json: bool,
    stdin: TextIO,
    stdout: TextIO,
) -> int:
    return watch_stdin_events(
        stdin,
        stdout,
        as_json=as_json,
        existing_assertions=_load_existing_assertions(existing_assertions_path),
    )


def _load_or_empty_review_queue(path: str) -> ReviewQueue:
    queue_path = Path(path)
    if not queue_path.exists():
        return ReviewQueue.empty()
    return load_review_queue(queue_path)


def _run_review_enqueue(
    path: str,
    queue_path: str,
    existing_assertions_path: str | None,
    as_json: bool,
    stdout: TextIO,
) -> int:
    queue = _load_or_empty_review_queue(queue_path)
    before = len(queue.items)
    with Path(path).open("r", encoding="utf-8") as handle:
        result = scan_jsonl_events(
            handle,
            source=path,
            existing_assertions=_load_existing_assertions(existing_assertions_path),
        )
    updated = enqueue_scan_result(result, queue)
    save_review_queue(queue_path, updated)
    enqueued = len(updated.items) - before
    if as_json:
        _print_json(
            {
                "review_version": updated.review_version,
                "queue_path": queue_path,
                "enqueued_items": enqueued,
                "queue": updated.to_dict(),
                "scan_summary": result.summary.to_dict(),
            },
            stdout,
        )
    else:
        print(
            f"{updated.review_version}: {enqueued} item(s) enqueued; "
            f"{len(updated.items)} total",
            file=stdout,
        )
    return 0


def _run_review_list(queue_path: str, as_json: bool, stdout: TextIO) -> int:
    queue = _load_or_empty_review_queue(queue_path)
    if as_json:
        _print_json(queue.to_dict(), stdout)
    else:
        print(
            f"{queue.review_version}: {len(queue.items)} review item(s)",
            file=stdout,
        )
        for item in queue.items:
            print(
                f"- {item.status.value} item={item.item_id} "
                f"event={item.event_id} findings={item.finding_count}",
                file=stdout,
            )
    return 0


def _receipt_for_item(queue: ReviewQueue, item_id: str) -> dict[str, Any]:
    for item in queue.items:
        if item.item_id != item_id:
            continue
        if item.receipt_id is None:
            raise ValueError("review item has no receipt")
        for receipt in queue.receipts:
            if receipt.receipt_id == item.receipt_id:
                return receipt.to_dict()
    raise ValueError(f"review item not found: {item_id}")


def _run_review_decision(
    command: str,
    queue_path: str,
    item_id: str,
    reason: str,
    reviewer: str,
    as_json: bool,
    stdout: TextIO,
) -> int:
    queue = _load_or_empty_review_queue(queue_path)
    if command == "allow":
        updated = allow_review_item(
            queue,
            item_id,
            reason=reason,
            reviewer=reviewer,
        )
    else:
        updated = reject_review_item(
            queue,
            item_id,
            reason=reason,
            reviewer=reviewer,
        )
    save_review_queue(queue_path, updated)
    receipt = _receipt_for_item(updated, item_id)
    if as_json:
        _print_json(receipt, stdout)
    else:
        print(
            f"{receipt['decision']} item={item_id} receipt={receipt['receipt_id']}",
            file=stdout,
        )
    return 0


def _run_review_preview(queue_path: str, as_json: bool, stdout: TextIO) -> int:
    queue = _load_or_empty_review_queue(queue_path)
    preview = trusted_read_preview(queue)
    if as_json:
        _print_json(preview.to_dict(), stdout)
    else:
        print(
            f"{preview.preview_version}: {len(preview.items)} preview item(s)",
            file=stdout,
        )
        for item in preview.items:
            print(
                f"- {item.preview_status} item={item.item_id} "
                f"event={item.event_id}",
                file=stdout,
            )
    return 0


def _run_conformance(adapter: str, as_json: bool, stdout: TextIO) -> int:
    if adapter != "demo":
        raise ValueError(f"unsupported adapter: {adapter}")
    result = run_adapter_conformance(demo_memory_adapter())
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        status = "passed" if result.passed else "failed"
        print(
            f"{result.adapter_name} {result.adapter_version}: {status}",
            file=stdout,
        )
        for check in result.checks:
            marker = "ok" if check.passed else "fail"
            print(f"- {marker}: {check.name}: {check.message}", file=stdout)
    return 0 if result.passed else 1


def _run_demo_poison(as_json: bool, stdout: TextIO) -> int:
    result = run_poison_demo()
    payload = result.to_dict()
    outcome = result.outcome()
    if as_json:
        _print_json(payload, stdout)
    else:
        print(f"{result.demo_version}: {result.scenario.scenario_id}", file=stdout)
        print(
            f"- naive answer: {outcome['naive_answer']} "
            f"(source of record: {outcome['source_of_record_answer']})",
            file=stdout,
        )
        print(
            f"- firewall high-risk events: {outcome['firewall_high_risk_events']}",
            file=stdout,
        )
        print(
            f"- pending/rejected preview items: "
            f"{outcome['pending_preview_items']}/"
            f"{outcome['rejected_preview_items']}",
            file=stdout,
        )
        print(
            f"- explicit override preview items: "
            f"{outcome['override_preview_items']}",
            file=stdout,
        )
    return 0


def _run_proxy_reference(mode: str, as_json: bool, stdout: TextIO) -> int:
    result = run_reference_proxy(mode)
    outcome = result.outcome()
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(f"{result.proxy_version}: reference proxy {result.mode.value}", file=stdout)
        print(
            f"- native answer: {outcome['native_answer']}",
            file=stdout,
        )
        print(
            f"- governed context answer: {outcome['governed_context_answer']}",
            file=stdout,
        )
        print(
            f"- high-risk events: {outcome['high_risk_events']}; "
            f"suppressed native writes: "
            f"{len(outcome['suppressed_native_event_ids'])}",
            file=stdout,
        )
    return 0


def _run_report_demo(output_dir: str, as_json: bool, stdout: TextIO) -> int:
    report = generate_demo_report()
    bundle = write_report_bundle(report, output_dir)
    if as_json:
        _print_json(bundle.to_dict(), stdout)
    else:
        print(f"{report.report_version}: {report.title}", file=stdout)
        print(f"- html: {bundle.html_path}", file=stdout)
        print(f"- report json: {bundle.report_json_path}", file=stdout)
        print(f"- redacted share: {bundle.redacted_export_path}", file=stdout)
        print(
            f"- high-risk events: {report.summary.high_risk_events}; "
            f"suppressed native writes: {report.summary.suppressed_native_writes}",
            file=stdout,
        )
    return 0


def _candidate_content(content: str | None, content_file: str | None) -> str:
    if content is not None:
        return content
    if content_file is not None:
        return Path(content_file).read_text(encoding="utf-8")
    raise ValueError("either content or content_file is required")


def _run_adapter_observe_memory(
    content: str | None,
    content_file: str | None,
    target_namespace: str,
    actor: str,
    user_or_tenant_scope: str,
    source_type: str,
    source_id: str,
    source_authority: str,
    operation: str,
    adapter_name: str,
    state_dir: str | None,
    as_json: bool,
    stdout: TextIO,
) -> int:
    result = observe_memory_candidate(
        content=_candidate_content(content, content_file),
        target_namespace=target_namespace,
        actor=actor,
        user_or_tenant_scope=user_or_tenant_scope,
        source_type=SourceType(source_type),
        source_id=source_id,
        source_authority=SourceAuthority(source_authority),
        operation=MemoryOperation(operation),
        adapter_name=adapter_name,
        state_dir=state_dir,
    )
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        item = result.observation
        categories = ", ".join(item.risk_categories) or "none"
        detectors = ", ".join(item.detector_names) or "none"
        print(f"{result.bridge_version}: adapter observe-memory", file=stdout)
        print(f"- state dir: {result.state_dir}", file=stdout)
        print(f"- adapter: {item.adapter_name}", file=stdout)
        print(f"- row: {item.row_number}", file=stdout)
        print(f"- handle: {item.event_ref}", file=stdout)
        print(f"- target: {item.target_namespace}", file=stdout)
        print(f"- source authority: {item.source_authority}", file=stdout)
        print(f"- operation: {item.operation}", file=stdout)
        print(f"- level: {item.level}", file=stdout)
        print(f"- disposition: {item.highest_disposition}", file=stdout)
        print(f"- findings: {item.finding_count}", file=stdout)
        print(f"- contradictions: {item.contradiction_count}", file=stdout)
        print(f"- risks: {categories}", file=stdout)
        print(f"- detectors: {detectors}", file=stdout)
        print("- observe-only: true", file=stdout)
        print("- raw content included: false", file=stdout)
    return 1 if result.observation.level == "high_risk" else 0


def _run_adapter_observations(
    state_dir: str | None,
    limit: int,
    as_json: bool,
    stdout: TextIO,
) -> int:
    result = recent_adapter_observations(state_dir=state_dir, limit=limit)
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(f"{result.bridge_version}: adapter observations", file=stdout)
        print(f"- state dir: {result.state_dir}", file=stdout)
        print(f"- total observations: {result.total_observations}", file=stdout)
        print(f"- high-risk: {result.high_risk_observations}", file=stdout)
        print(f"- warn: {result.warn_observations}", file=stdout)
        print(f"- pass: {result.pass_observations}", file=stdout)
        print(f"- returned: {result.returned_observations}", file=stdout)
        print("- observe-only: true", file=stdout)
        print("- raw content included: false", file=stdout)
        for item in result.observations:
            categories = ", ".join(item.risk_categories) or "none"
            detectors = ", ".join(item.detector_names) or "none"
            print(
                f"- #{item.row_number} {item.recorded_at} "
                f"{item.level}/{item.highest_disposition} "
                f"{item.adapter_name} -> {item.target_namespace}",
                file=stdout,
            )
            print(f"  version: {item.recorded_bridge_version}", file=stdout)
            print(f"  handle: {item.event_ref}", file=stdout)
            print(
                f"  findings: {item.finding_count}; "
                f"contradictions: {item.contradiction_count}; "
                f"risks: {categories}",
                file=stdout,
            )
            print(f"  detectors: {detectors}", file=stdout)
    has_high_risk = any(item.level == "high_risk" for item in result.observations)
    return 1 if has_high_risk else 0


def _run_adapter_report(
    state_dir: str | None,
    output_dir: str,
    limit: int,
    open_report: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    report = generate_adapter_report(state_dir=state_dir, limit=limit)
    bundle = write_adapter_report_bundle(report, output_dir)
    if open_report:
        webbrowser.open(bundle.html_path.resolve().as_uri())
    if as_json:
        _print_json(bundle.to_dict(), stdout)
    else:
        print(f"{report.report_version}: {report.title}", file=stdout)
        print(f"- overall: {report.setup.overall_status}", file=stdout)
        print(f"- html: {bundle.html_path}", file=stdout)
        print(f"- report json: {bundle.report_json_path}", file=stdout)
        print(f"- redacted share: {bundle.redacted_export_path}", file=stdout)
        print(f"- observations: {report.summary.total_observations}", file=stdout)
        print(f"- high-risk: {report.summary.high_risk_observations}", file=stdout)
        print(f"- warn: {report.summary.warn_observations}", file=stdout)
        print(f"- pass: {report.summary.pass_observations}", file=stdout)
        print(f"- returned rows: {report.summary.returned_observations}", file=stdout)
        print("- observe-only: true", file=stdout)
        if report.next_steps:
            print("- next steps:", file=stdout)
            for step in report.next_steps:
                print(f"  - {step}", file=stdout)
    return 1 if report.summary.high_risk_observations > 0 else 0


def _run_hermes_status(
    state_dir: str | None,
    as_json: bool,
    stdout: TextIO,
) -> int:
    status = summarize_hermes_observations(state_dir=state_dir)
    if as_json:
        _print_json(status.to_dict(), stdout)
    else:
        print(f"{status.integration_version}: Hermes hook alpha", file=stdout)
        print(f"- state dir: {status.state_dir}", file=stdout)
        print(f"- observations: {status.total_observations}", file=stdout)
        print(
            f"- current version observations: "
            f"{status.current_version_observations}",
            file=stdout,
        )
        print(
            f"- legacy/unknown version observations: "
            f"{status.legacy_version_observations}",
            file=stdout,
        )
        print(f"- high-risk: {status.high_risk_observations}", file=stdout)
        print(f"- warn: {status.warn_observations}", file=stdout)
        print(f"- pass: {status.pass_observations}", file=stdout)
        print("- observe-only: true", file=stdout)
        if status.latest_recorded_at is not None:
            print(f"- latest: {status.latest_recorded_at}", file=stdout)
    return 0 if status.high_risk_observations == 0 else 1


def _run_hermes_observations(
    state_dir: str | None,
    limit: int,
    current_version_only: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    result = recent_hermes_observations(
        state_dir=state_dir,
        limit=limit,
        current_version_only=current_version_only,
    )
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(f"{result.integration_version}: Hermes observations", file=stdout)
        print(f"- state dir: {result.state_dir}", file=stdout)
        print(f"- observation scope: {result.observation_scope}", file=stdout)
        print(f"- total observations: {result.total_observations}", file=stdout)
        print(f"- all-history high-risk: {result.high_risk_observations}", file=stdout)
        print(f"- all-history warn: {result.warn_observations}", file=stdout)
        print(f"- all-history pass: {result.pass_observations}", file=stdout)
        print(f"- matching observations: {result.matching_observations}", file=stdout)
        print(
            f"- matching high-risk: {result.matching_high_risk_observations}",
            file=stdout,
        )
        print(f"- matching warn: {result.matching_warn_observations}", file=stdout)
        print(f"- matching pass: {result.matching_pass_observations}", file=stdout)
        print(f"- returned: {result.returned_observations}", file=stdout)
        print("- observe-only: true", file=stdout)
        for item in result.observations:
            categories = ", ".join(item.risk_categories) or "none"
            detectors = ", ".join(item.detector_names) or "none"
            print(
                f"- #{item.row_number} {item.recorded_at} "
                f"{item.level}/{item.highest_disposition} "
                f"{item.tool_name} -> {item.target_namespace}",
                file=stdout,
            )
            print(f"  version: {item.recorded_integration_version}", file=stdout)
            print(f"  handle: {item.event_ref}", file=stdout)
            print(
                f"  findings: {item.finding_count}; "
                f"contradictions: {item.contradiction_count}; "
                f"risks: {categories}",
                file=stdout,
            )
            print(f"  detectors: {detectors}", file=stdout)
    has_high_risk = any(
        item.level == "high_risk" for item in result.observations
    )
    return 1 if has_high_risk else 0


def _run_hermes_checkup(
    hermes_home: str | None,
    state_dir: str | None,
    limit: int,
    write_sample: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    result = check_hermes_setup(
        hermes_home=hermes_home,
        state_dir=state_dir,
        limit=limit,
        write_sample=write_sample,
    )
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        print(f"{result.integration_version}: Hermes checkup", file=stdout)
        print(f"- overall: {result.overall_status}", file=stdout)
        print(f"- Hermes home: {result.hermes_home}", file=stdout)
        print(f"- plugin shim: {result.plugin_dir}", file=stdout)
        print(
            f"- config lists plugin: {result.config_mentions_plugin}",
            file=stdout,
        )
        print(f"- state dir: {result.state_dir}", file=stdout)
        print(f"- observations: {result.status.total_observations}", file=stdout)
        print(
            f"- current version observations: "
            f"{result.status.current_version_observations}",
            file=stdout,
        )
        print(
            f"- legacy/unknown version observations: "
            f"{result.status.legacy_version_observations}",
            file=stdout,
        )
        print(f"- high-risk: {result.status.high_risk_observations}", file=stdout)
        print(f"- sample written: {result.sample_written}", file=stdout)
        print("- checks:", file=stdout)
        for check in result.checks:
            print(f"  - {check.status}: {check.name} - {check.message}", file=stdout)
        if result.next_steps:
            print("- next steps:", file=stdout)
            for step in result.next_steps:
                print(f"  - {step}", file=stdout)
        print("- observe-only: true", file=stdout)
    return 0 if result.overall_status == "ready" else 1


def _run_hermes_report(
    hermes_home: str | None,
    state_dir: str | None,
    output_dir: str,
    limit: int,
    write_sample: bool,
    current_version_only: bool,
    open_report: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    report = generate_hermes_report(
        hermes_home=hermes_home,
        state_dir=state_dir,
        limit=limit,
        write_sample=write_sample,
        current_version_only=current_version_only,
    )
    bundle = write_hermes_report_bundle(report, output_dir)
    if open_report:
        webbrowser.open(bundle.html_path.resolve().as_uri())
    if as_json:
        _print_json(bundle.to_dict(), stdout)
    else:
        print(f"{report.report_version}: {report.title}", file=stdout)
        print(f"- overall: {report.setup.overall_status}", file=stdout)
        print(f"- html: {bundle.html_path}", file=stdout)
        print(f"- report json: {bundle.report_json_path}", file=stdout)
        print(f"- redacted share: {bundle.redacted_export_path}", file=stdout)
        print(f"- observation scope: {report.summary.observation_scope}", file=stdout)
        print(f"- observations: {report.summary.total_observations}", file=stdout)
        print(
            f"- current version observations: "
            f"{report.summary.current_version_observations}",
            file=stdout,
        )
        print(
            f"- legacy/unknown version observations: "
            f"{report.summary.legacy_version_observations}",
            file=stdout,
        )
        print(
            f"- matching observations: {report.summary.matching_observations}",
            file=stdout,
        )
        print(
            f"- matching high-risk: "
            f"{report.summary.matching_high_risk_observations}",
            file=stdout,
        )
        print(f"- high-risk: {report.summary.high_risk_observations}", file=stdout)
        print(f"- returned rows: {report.summary.returned_observations}", file=stdout)
        print("- observe-only: true", file=stdout)
        if report.next_steps:
            print("- next steps:", file=stdout)
            for step in report.next_steps:
                print(f"  - {step}", file=stdout)
    if (
        report.setup.overall_status == "ready"
        and report.summary.matching_observations > 0
        and report.summary.matching_high_risk_observations == 0
    ):
        return 0
    return 1


def _run_hermes_install_plugin(
    hermes_home: str | None,
    force: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    result = install_hermes_plugin_shim(hermes_home=hermes_home, force=force)
    if as_json:
        _print_json(result.to_dict(), stdout)
    else:
        action = "installed" if result.created else "updated"
        if not result.created and not result.updated:
            action = "already installed"
        print(
            f"{result.integration_version}: Hermes plugin shim {action}",
            file=stdout,
        )
        print(f"- plugin dir: {result.plugin_dir}", file=stdout)
        print(f"- manifest: {result.manifest_path}", file=stdout)
        print(f"- shim: {result.init_path}", file=stdout)
        print(f"- enable: {result.enable_command}", file=stdout)
        print("- observe-only: true", file=stdout)
    return 0


def _run_lineage_report(path: str, as_json: bool, stdout: TextIO) -> int:
    report = load_lineage_report(path)
    if as_json:
        _print_json(report.to_dict(), stdout)
    else:
        summary = report.summary
        print(
            f"{report.lineage_version}: {report.provider} "
            f"{report.provider_version} lineage",
            file=stdout,
        )
        print(f"- candidates: {summary.candidates}", file=stdout)
        print(f"- persisted: {summary.persisted_candidates}", file=stdout)
        print(f"- retrieved: {summary.retrieved_candidates}", file=stdout)
        print(
            f"- downstream-used: {summary.downstream_used_candidates}",
            file=stdout,
        )
        print(
            f"- candidate-level verdicts: {summary.candidate_level_verdicts}",
            file=stdout,
        )
        print(
            f"- case-level-only candidates: {summary.case_level_only_candidates}",
            file=stdout,
        )
        print(
            f"- highest any-candidate disposition: "
            f"{summary.highest_any_candidate_disposition.value}",
            file=stdout,
        )
        print(
            f"- highest downstream-used disposition: "
            f"{summary.highest_downstream_used_candidate_disposition.value}",
            file=stdout,
        )
        print(
            f"- downstream-used escalated: "
            f"{summary.downstream_used_candidates_escalated}",
            file=stdout,
        )
        print(
            f"- downstream-used unscanned: "
            f"{summary.downstream_used_candidates_unscanned}",
            file=stdout,
        )
        for issue in report.issues:
            print(
                f"- ISSUE {issue.code}: {issue.message}",
                file=stdout,
            )
    return 1 if report.issues else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Memory Firewall CLI."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _run_doctor(bool(args.as_json), sys.stdout)
    if args.command == "schema":
        return _run_schema(str(args.name), sys.stdout)
    if args.command == "risks":
        return _run_risks(bool(args.as_json), sys.stdout)
    if args.command == "claims":
        return _run_claims(bool(args.as_json), sys.stdout)
    if args.command == "policy":
        return _run_policy(bool(args.as_json), sys.stdout)
    if args.command == "detect":
        return _run_detect(str(args.event), bool(args.as_json), sys.stdin, sys.stdout)
    if args.command == "analyze":
        existing_assertions_path = (
            None
            if args.existing_assertions is None
            else str(args.existing_assertions)
        )
        return _run_analyze(
            str(args.event),
            existing_assertions_path,
            bool(args.as_json),
            sys.stdin,
            sys.stdout,
        )
    if args.command == "scan":
        existing_assertions_path = (
            None
            if args.existing_assertions is None
            else str(args.existing_assertions)
        )
        return _run_scan(
            str(args.path),
            existing_assertions_path,
            bool(args.as_json),
            bool(args.summary_only),
            sys.stdout,
        )
    if args.command == "watch":
        existing_assertions_path = (
            None
            if args.existing_assertions is None
            else str(args.existing_assertions)
        )
        return _run_watch(
            existing_assertions_path,
            bool(args.as_json),
            sys.stdin,
            sys.stdout,
        )
    if args.command == "review":
        review_command = str(args.review_command)
        if review_command == "enqueue":
            existing_assertions_path = (
                None
                if args.existing_assertions is None
                else str(args.existing_assertions)
            )
            return _run_review_enqueue(
                str(args.path),
                str(args.queue),
                existing_assertions_path,
                bool(args.as_json),
                sys.stdout,
            )
        if review_command == "list":
            return _run_review_list(str(args.queue), bool(args.as_json), sys.stdout)
        if review_command in {"allow", "reject"}:
            return _run_review_decision(
                review_command,
                str(args.queue),
                str(args.item_id),
                str(args.reason),
                str(args.reviewer),
                bool(args.as_json),
                sys.stdout,
            )
        if review_command == "trusted-read-preview":
            return _run_review_preview(
                str(args.queue),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown review command: {review_command}")
    if args.command == "conformance":
        return _run_conformance(str(args.adapter), bool(args.as_json), sys.stdout)
    if args.command == "demo":
        demo_command = str(args.demo_command)
        if demo_command == "poison":
            return _run_demo_poison(bool(args.as_json), sys.stdout)
        parser.error(f"unknown demo command: {demo_command}")
    if args.command == "proxy":
        proxy_command = str(args.proxy_command)
        if proxy_command == "reference":
            return _run_proxy_reference(
                str(args.mode),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown proxy command: {proxy_command}")
    if args.command == "report":
        report_command = str(args.report_command)
        if report_command == "demo":
            return _run_report_demo(
                str(args.out),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown report command: {report_command}")
    if args.command == "adapter":
        adapter_command = str(args.adapter_command)
        if adapter_command == "observe-memory":
            state_dir = None if args.state_dir is None else str(args.state_dir)
            content = None if args.content is None else str(args.content)
            content_file = (
                None if args.content_file is None else str(args.content_file)
            )
            return _run_adapter_observe_memory(
                content,
                content_file,
                str(args.target),
                str(args.actor),
                str(args.scope),
                str(args.source_type),
                str(args.source_id),
                str(args.source_authority),
                str(args.operation),
                str(args.adapter_name),
                state_dir,
                bool(args.as_json),
                sys.stdout,
            )
        if adapter_command == "observations":
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_adapter_observations(
                state_dir,
                int(args.limit),
                bool(args.as_json),
                sys.stdout,
            )
        if adapter_command == "report":
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_adapter_report(
                state_dir,
                str(args.out),
                int(args.limit),
                bool(args.open_report),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown adapter command: {adapter_command}")
    if args.command == "hermes":
        hermes_command = str(args.hermes_command)
        if hermes_command == "status":
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_hermes_status(
                state_dir,
                bool(args.as_json),
                sys.stdout,
            )
        if hermes_command == "observations":
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_hermes_observations(
                state_dir,
                int(args.limit),
                bool(args.current_version_only),
                bool(args.as_json),
                sys.stdout,
            )
        if hermes_command == "checkup":
            hermes_home = None if args.hermes_home is None else str(args.hermes_home)
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_hermes_checkup(
                hermes_home,
                state_dir,
                int(args.limit),
                bool(args.write_sample),
                bool(args.as_json),
                sys.stdout,
            )
        if hermes_command == "report":
            hermes_home = None if args.hermes_home is None else str(args.hermes_home)
            state_dir = None if args.state_dir is None else str(args.state_dir)
            return _run_hermes_report(
                hermes_home,
                state_dir,
                str(args.out),
                int(args.limit),
                bool(args.write_sample),
                bool(args.current_version_only),
                bool(args.open_report),
                bool(args.as_json),
                sys.stdout,
            )
        if hermes_command == "install-plugin":
            hermes_home = None if args.hermes_home is None else str(args.hermes_home)
            return _run_hermes_install_plugin(
                hermes_home,
                bool(args.force),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown hermes command: {hermes_command}")
    if args.command == "lineage":
        lineage_command = str(args.lineage_command)
        if lineage_command == "report":
            return _run_lineage_report(
                str(args.path),
                bool(args.as_json),
                sys.stdout,
            )
        parser.error(f"unknown lineage command: {lineage_command}")
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
