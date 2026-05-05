from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class JsonlOutputConfig:
    output_file: str | None
    output_line_buffered: bool
    output_file_sync_every: int


class JsonlWriter:
    def __init__(
        self,
        output_file: str | None = None,
        line_buffered: bool = False,
        file_sync_every: int = 100,
    ) -> None:
        self._output_file = output_file
        self._line_buffered = line_buffered
        self._file_sync_every = max(1, int(file_sync_every))
        self._file_handle = None
        self._since_flush = 0

        if self._output_file:
            self._file_handle = open(self._output_file, "a", encoding="utf-8")

    def write_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n"

        sys.stdout.write(line)
        if self._line_buffered:
            sys.stdout.flush()

        if self._file_handle is not None:
            self._file_handle.write(line)
            self._since_flush += 1

            if self._line_buffered or self._since_flush >= self._file_sync_every:
                self._file_handle.flush()
                self._since_flush = 0

    def close(self) -> None:
        if self._file_handle is not None:
            self._file_handle.flush()
            self._file_handle.close()
            self._file_handle = None


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _add_common_run_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bind-host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, required=True, help="Listen port")
    parser.add_argument("--output-file", default=None, help="Write JSONL events to file")
    parser.add_argument(
        "--output-line-buffered",
        action="store_true",
        help="Flush after every JSONL line (stdout and file sinks)",
    )
    parser.add_argument(
        "--output-file-sync-every",
        type=_positive_int,
        default=100,
        help=(
            "Flush JSONL output file every N events (default: 100). "
            "Lower values reduce potential data loss window at higher I/O cost. "
            "Ignored when --output-file is not set; overridden by --output-line-buffered."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        p = subparsers.add_parser(cmd)
        _add_common_run_flags(p)

    return parser


def _build_output_config(args: argparse.Namespace) -> JsonlOutputConfig:
    return JsonlOutputConfig(
        output_file=args.output_file,
        output_line_buffered=bool(args.output_line_buffered),
        output_file_sync_every=int(args.output_file_sync_every),
    )


async def _run(args: argparse.Namespace) -> int:
    output_cfg = _build_output_config(args)
    writer = JsonlWriter(
        output_file=output_cfg.output_file,
        line_buffered=output_cfg.output_line_buffered,
        file_sync_every=output_cfg.output_file_sync_every,
    )
    try:
        writer.write_event({"event": "startup", "command": args.command, "port": args.port})
        await asyncio.sleep(0)
        return 0
    finally:
        writer.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
