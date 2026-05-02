#!/usr/bin/env python3
"""
honeypot-foundry CLI entrypoint.

Adds --output-line-buffered support to force flush-after-write behavior for
JSONL stdout/file sinks on run commands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, TextIO


class JsonlWriter:
    def __init__(self, output_file: Optional[str] = None, line_buffered: bool = False) -> None:
        self._line_buffered = line_buffered
        self._stdout: TextIO = sys.stdout
        self._fh: Optional[TextIO] = None
        if output_file:
            path = Path(output_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("a", encoding="utf-8")

    def emit(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        self._stdout.write(line + "\n")
        if self._line_buffered:
            self._stdout.flush()

        if self._fh is not None:
            self._fh.write(line + "\n")
            if self._line_buffered:
                self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    sub = parser.add_subparsers(dest="command")

    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        p = sub.add_parser(cmd)
        p.add_argument("--output-file", default=None, help="Write JSONL events to file")
        p.add_argument(
            "--output-line-buffered",
            action="store_true",
            help=(
                "Flush stdout and --output-file after each JSONL line "
                "(safer durability during abrupt restarts, higher I/O overhead)."
            ),
        )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    writer = JsonlWriter(
        output_file=getattr(args, "output_file", None),
        line_buffered=bool(getattr(args, "output_line_buffered", False)),
    )
    try:
        writer.emit({"event": "startup", "command": args.command})
    finally:
        writer.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
