import argparse
import asyncio
import gzip
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cli import build_parser
from collectors.forwarder import EventForwarder
from honeypots.api_honeypot import run_api_honeypot
from honeypots.ftp_honeypot import run_ftp_honeypot
from honeypots.http_honeypot import run_http_honeypot
from honeypots.rdp_honeypot import run_rdp_honeypot
from honeypots.ssh_honeypot import run_ssh_honeypot


class EventWriter:
    def __init__(self, output_file: Optional[str] = None, gzip_output: bool = False):
        self.output_file = output_file
        self.gzip_output = gzip_output
        self._fh = None

        if self.output_file:
            path = Path(self.output_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            if self.gzip_output:
                self._fh = gzip.open(path, mode="at", encoding="utf-8")
            else:
                self._fh = open(path, mode="a", encoding="utf-8")

    def write_event(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        print(line, flush=True)

        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
            finally:
                self._fh.close()
                self._fh = None


async def _run(args: argparse.Namespace) -> int:
    writer = EventWriter(output_file=getattr(args, "output_file", None), gzip_output=getattr(args, "gzip_output", False))
    forwarder = EventForwarder.from_env()

    def emit(event: Dict[str, Any]) -> None:
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        writer.write_event(event)
        forwarder.forward(event)

    stop_event = asyncio.Event()

    def _handle_signal(*_):
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass

    service_task = None
    try:
        if args.command == "run-ssh":
            service_task = asyncio.create_task(run_ssh_honeypot(args, emit, stop_event))
        elif args.command == "run-http":
            service_task = asyncio.create_task(run_http_honeypot(args, emit, stop_event))
        elif args.command == "run-api":
            service_task = asyncio.create_task(run_api_honeypot(args, emit, stop_event))
        elif args.command == "run-ftp":
            service_task = asyncio.create_task(run_ftp_honeypot(args, emit, stop_event))
        elif args.command == "run-rdp":
            service_task = asyncio.create_task(run_rdp_honeypot(args, emit, stop_event))
        else:
            raise ValueError(f"Unsupported command: {args.command}")

        await stop_event.wait()
        if service_task:
            service_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await service_task

        return 0
    finally:
        writer.close()
        forwarder.close()


def _add_gzip_flag(parser: argparse.ArgumentParser) -> None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in action.choices.items():
                if name.startswith("run-"):
                    subparser.add_argument(
                        "--gzip-output",
                        action="store_true",
                        help="Write --output-file as gzip-compressed JSONL (.jsonl.gz)",
                    )


def main() -> int:
    parser = build_parser()
    _add_gzip_flag(parser)
    args = parser.parse_args()

    if not hasattr(args, "command"):
        parser.print_help()
        return 2

    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
