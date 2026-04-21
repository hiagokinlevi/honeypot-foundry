#!/usr/bin/env python3
"""Command-line interface for honeypot-foundry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import ValidationError, validator_for


DEFAULT_SCHEMA_CANDIDATES = [
    "attack-event.schema.json",
    "attack_event.schema.json",
    "attack-event.json",
    "attack_event.json",
    "event.schema.json",
]


def _load_attack_event_schema() -> dict:
    repo_root = Path(__file__).resolve().parent
    schemas_dir = repo_root / "schemas"

    if not schemas_dir.exists():
        raise FileNotFoundError(f"Schemas directory not found: {schemas_dir}")

    for name in DEFAULT_SCHEMA_CANDIDATES:
        candidate = schemas_dir / name
        if candidate.exists():
            with candidate.open("r", encoding="utf-8") as f:
                return json.load(f)

    # fallback: use first JSON schema-like file in schemas/
    json_files = sorted(schemas_dir.glob("*.json"))
    if json_files:
        with json_files[0].open("r", encoding="utf-8") as f:
            return json.load(f)

    raise FileNotFoundError(
        f"No schema JSON file found in {schemas_dir}. Tried: {', '.join(DEFAULT_SCHEMA_CANDIDATES)}"
    )


def _validate_events_file(file_path: Path) -> int:
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2

    schema = _load_attack_event_schema()
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)

    valid_count = 0
    invalid_lines: list[int] = []

    with file_path.open("r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                invalid_lines.append(line_no)
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines.append(line_no)
                continue

            try:
                validator.validate(record)
                valid_count += 1
            except ValidationError:
                invalid_lines.append(line_no)

    print(f"Valid events: {valid_count}")
    if invalid_lines:
        print(f"Invalid records: {len(invalid_lines)}")
        print("Invalid line numbers: " + ", ".join(str(n) for n in invalid_lines))
        return 1

    print("Invalid records: 0")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot", description="honeypot-foundry CLI")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser(
        "validate-events",
        help="Validate JSONL event records against canonical attack event schema",
    )
    validate_parser.add_argument("--file", required=True, help="Path to events JSONL file")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "validate-events":
        return _validate_events_file(Path(args.file))

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
