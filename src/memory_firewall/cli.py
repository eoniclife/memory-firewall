"""Command-line entry point for Memory Firewall."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from .adapters import demo_memory_adapter
from .analysis import MemoryStateAssertion, analyze_memory_state
from .claim_budget import claim_budget
from .conformance import run_adapter_conformance
from .detectors import default_detector_pack, run_detectors
from .doctor import doctor_report
from .models import MemoryEvent
from .policy import DISPOSITION_ORDER, SEVERITY_ORDER, PolicyConfig
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
    adapter_capability_report_schema,
    detector_pack_schema,
    detector_result_schema,
    evidence_span_schema,
    event_schema,
    finding_schema,
    override_receipt_schema,
    policy_schema,
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
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
