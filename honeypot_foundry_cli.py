from __future__ import annotations

import argparse
import os


def _current_schema_version() -> str:
    return os.getenv("HONEYPOT_EVENT_SCHEMA_VERSION", "1.0")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument(
        "--event-schema-version",
        default=_current_schema_version(),
        help=(
            "Schema version stamped onto all emitted telemetry events "
            "(default: current schema version)."
        ),
    )

    sub = parser.add_subparsers(dest="command")
    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        p = sub.add_parser(cmd)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--output-file")

    return parser


def build_event(base_event: dict, event_schema_version: str | None = None) -> dict:
    event = dict(base_event)
    event["schema_version"] = event_schema_version or _current_schema_version()
    return event


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _ = build_event({"event_type": "startup"}, args.event_schema_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
