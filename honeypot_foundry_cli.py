#!/usr/bin/env python3
"""CLI entrypoint for honeypot-foundry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cli.schema_validator import validate_event_schema


def _read_single_event(event_file: str | None) -> dict:
    if event_file:
        raw = Path(event_file).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()

    raw = raw.strip()
    if not raw:
        raise ValueError("no event payload provided")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("event must be a JSON object")

    return parsed


def _print_validate_event_result(fmt: str, ok: bool, path: str | None = None, message: str | None = None) -> None:
    if fmt == "json":
        payload = {
            "valid": ok,
            "error_path": path,
            "message": message,
        }
        print(json.dumps(payload, separators=(",", ":")))
        return

    # text
    if ok:
        print("valid=true")
    else:
        p = path or "<root>"
        m = message or "schema validation failed"
        print(f"valid=false path={p} message={m}")


def cmd_validate_event(args: argparse.Namespace) -> int:
    try:
        event = _read_single_event(args.event_file)
    except Exception as exc:
        _print_validate_event_result(args.format, False, "<input>", str(exc))
        return 2

    result = validate_event_schema(event)

    # Support existing utility return styles while keeping this command small.
    if isinstance(result, tuple):
        ok = bool(result[0])
        path = result[1] if len(result) > 1 else None
        message = result[2] if len(result) > 2 else None
    elif isinstance(result, dict):
        ok = bool(result.get("valid", result.get("ok", False)))
        path = result.get("error_path") or result.get("path")
        message = result.get("message") or result.get("error")
    else:
        ok = bool(result)
        path = None
        message = None

    _print_validate_event_result(args.format, ok, path, message)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    subparsers = parser.add_subparsers(dest="command")

    validate_event = subparsers.add_parser(
        "validate-event",
        help="Validate a single JSON event against the event schema",
    )
    validate_event.add_argument(
        "--event-file",
        help="Path to a JSON file containing one event object. If omitted, read from stdin.",
    )
    validate_event.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for validation result",
    )
    validate_event.set_defaults(func=cmd_validate_event)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
