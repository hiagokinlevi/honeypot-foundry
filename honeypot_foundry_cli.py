#!/usr/bin/env python3
"""honeypot CLI entrypoint."""

from __future__ import annotations

import argparse
from typing import Any, Dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument(
        "--siem-forward-timeout-seconds",
        type=float,
        default=5.0,
        help=(
            "Timeout in seconds for outbound SIEM forwarding network calls "
            "(e.g., Splunk HEC, Elastic bulk). Default: 5.0"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    run_http = subparsers.add_parser("run-http")
    run_http.add_argument("--port", type=int, default=8080)
    run_http.add_argument("--output-file", default="events.jsonl")

    return parser


def build_forwarder_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "siem_forward_timeout_seconds": args.siem_forward_timeout_seconds,
    }


def _post_splunk_event(session: Any, endpoint: str, payload: Dict[str, Any], timeout_seconds: float) -> Any:
    return session.post(endpoint, json=payload, timeout=timeout_seconds)


def _post_elastic_bulk(session: Any, endpoint: str, data: str, timeout_seconds: float) -> Any:
    return session.post(endpoint, data=data, timeout=timeout_seconds)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    _ = build_forwarder_config(args)
    # Existing runtime dispatch omitted for brevity in this task-focused update.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
