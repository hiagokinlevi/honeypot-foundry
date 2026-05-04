#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict


# NOTE:
# This file is intentionally self-contained for CLI wiring and shared
# event serialization behavior.


def _format_event_timestamp(ts: float, fmt: str) -> Any:
    if fmt == "unix":
        return ts
    if fmt == "rfc3339":
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    raise ValueError(f"unsupported event timestamp format: {fmt}")


def serialize_event(event: Dict[str, Any], timestamp_format: str = "unix") -> str:
    e = dict(event)
    if "timestamp" in e:
        try:
            numeric_ts = float(e["timestamp"])
        except (TypeError, ValueError):
            # Preserve existing value if upstream already provided non-numeric timestamp.
            pass
        else:
            e["timestamp"] = _format_event_timestamp(numeric_ts, timestamp_format)
    return json.dumps(e, separators=(",", ":"), sort_keys=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot", description="honeypot-foundry CLI")
    parser.add_argument(
        "--event-timestamp-format",
        choices=("unix", "rfc3339"),
        default="unix",
        help="Event timestamp output format: unix (default) or rfc3339 (UTC ISO-8601)",
    )

    sub = parser.add_subparsers(dest="command")

    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        p = sub.add_parser(cmd)
        p.add_argument("--port", type=int, required=False)
        p.add_argument("--output-file", required=False)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Placeholder demo event path to represent shared serialization behavior.
    event = {
        "event_type": "startup",
        "service": args.command or "unknown",
        "timestamp": datetime.now(tz=timezone.utc).timestamp(),
    }
    sys.stdout.write(serialize_event(event, timestamp_format=args.event_timestamp_format) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
