#!/usr/bin/env python3
"""Replay previously captured honeypot attack events to a SIEM/webhook endpoint.

Usage example:
  python scripts/replay_events.py \
    --input-file training/sample_attack_events.jsonl \
    --target-url http://localhost:9000/events \
    --replay-rate 2 \
    --max-events 10
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Iterable, Iterator

import requests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay honeypot attack events from JSONL to a SIEM/webhook endpoint."
    )
    parser.add_argument(
        "--input-file",
        default="training/sample_attack_events.jsonl",
        help="Path to input JSONL file containing attack events (default: training/sample_attack_events.jsonl)",
    )
    parser.add_argument(
        "--target-url",
        required=True,
        help="Target SIEM/webhook URL that accepts JSON POST payloads.",
    )
    parser.add_argument(
        "--replay-rate",
        type=float,
        default=1.0,
        help="Events per second to replay (default: 1.0).",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum number of events to send (default: all).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Optional extra HTTP header in KEY=VALUE format. Can be supplied multiple times.",
    )
    return parser.parse_args()


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[warn] skipping invalid JSON on line {line_no}: {exc}", file=sys.stderr)
                continue
            if not isinstance(payload, dict):
                print(f"[warn] skipping non-object JSON on line {line_no}", file=sys.stderr)
                continue
            yield payload


def parse_headers(values: Iterable[str]) -> dict:
    headers = {"Content-Type": "application/json"}
    for item in values:
        if "=" not in item:
            raise ValueError(f"Invalid --header value '{item}'. Expected KEY=VALUE.")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --header value '{item}'. Empty header key.")
        headers[key] = value
    return headers


def main() -> int:
    args = parse_args()

    input_path = Path(args.input_file)
    if not input_path.exists() or not input_path.is_file():
        print(f"[error] input file not found: {input_path}", file=sys.stderr)
        return 2

    if args.replay_rate <= 0:
        print("[error] --replay-rate must be > 0", file=sys.stderr)
        return 2

    if args.max_events is not None and args.max_events <= 0:
        print("[error] --max-events must be > 0 when provided", file=sys.stderr)
        return 2

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    interval = 1.0 / args.replay_rate
    sent = 0
    failed = 0

    print(
        f"[info] replay start input={input_path} target={args.target_url} "
        f"rate={args.replay_rate}/s max_events={args.max_events or 'all'}"
    )

    for event in iter_jsonl(input_path):
        if args.max_events is not None and sent >= args.max_events:
            break

        start = time.monotonic()
        try:
            resp = requests.post(args.target_url, json=event, headers=headers, timeout=args.timeout)
            if 200 <= resp.status_code < 300:
                sent += 1
                print(f"[ok] event={sent} status={resp.status_code}")
            else:
                failed += 1
                print(
                    f"[warn] event={sent + failed} status={resp.status_code} body={resp.text[:200]!r}",
                    file=sys.stderr,
                )
        except requests.RequestException as exc:
            failed += 1
            print(f"[warn] event={sent + failed} request failed: {exc}", file=sys.stderr)

        elapsed = time.monotonic() - start
        sleep_for = interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

    print(f"[info] replay complete sent={sent} failed={failed}")
    return 0 if sent > 0 and failed == 0 else (1 if sent > 0 else 2)


if __name__ == "__main__":
    raise SystemExit(main())
