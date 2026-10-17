"""CLI: fuzz an MCP server over stdio or HTTP and print the verdict table."""
from __future__ import annotations

import argparse
import json
import sys

from .cases import CASES, get_cases
from .fuzzer import make_transport, run_fuzz


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fuzz an MCP server with malformed JSON-RPC payloads."
    )
    parser.add_argument(
        "--target", required=True,
        help="Target spec: 'stdio:<command>' or 'http:<url>'.",
    )
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Seconds to wait per case (default 3.0).")
    parser.add_argument("--case", action="append", default=None,
                        help="Run only this case (repeatable). Default: all.")
    parser.add_argument("--list-cases", action="store_true",
                        help="List fuzz cases and exit.")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    args = parser.parse_args(argv)

    if args.list_cases:
        for c in CASES:
            print(f"{c.name:18s} {c.description}")
        return 0

    transport, label = make_transport(args.target, args.timeout)
    report = run_fuzz(transport, label, get_cases(args.case))
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.table())
    return 0 if report.counts()["CRASH"] == 0 and report.counts()["HANG"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
