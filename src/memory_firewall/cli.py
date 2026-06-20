"""Command-line entry point for Memory Firewall."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from .adapters import demo_memory_adapter
from .claim_budget import claim_budget
from .conformance import run_adapter_conformance
from .detectors import default_detector_pack, run_detectors
from .doctor import doctor_report
from .models import MemoryEvent
from .policy import DISPOSITION_ORDER, SEVERITY_ORDER, PolicyConfig
from .schema import (
    adapter_capability_report_schema,
    detector_pack_schema,
    detector_result_schema,
    evidence_span_schema,
    event_schema,
    finding_schema,
    policy_schema,
    schema_bundle,
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
    if args.command == "conformance":
        return _run_conformance(str(args.adapter), bool(args.as_json), sys.stdout)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
