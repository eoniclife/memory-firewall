#!/usr/bin/env python3
"""Observe a caller-owned SQLite memory writer with Memory Firewall.

Run from a checkout with:

    python examples/generic_write_through_sqlite.py --workspace ./mf-sqlite-demo

The example keeps native memory writes in a local SQLite database, records
Memory Firewall adapter diagnostics next to it, and writes a local report
bundle. It does not replace, suppress, or approve the native writer.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from memory_firewall import run_sqlite_write_through_diagnostic


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Observe a simple caller-owned SQLite memory writer.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("memory-firewall-sqlite-example"),
        help="Directory for the native SQLite DB, adapter state, and report.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    summary = run_sqlite_write_through_diagnostic(args.workspace)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
