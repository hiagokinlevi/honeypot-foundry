import argparse
import asyncio
import hashlib
import json
import os
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def deterministic_event_id(event: Dict[str, Any]) -> str:
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class JsonlWriter:
    def __init__(
        self,
        output_file: Optional[str] = None,
        line_buffered: bool = False,
        fsync_interval: Optional[float] = None,
    ) -> None:
        self.output_file = output_file
        self.line_buffered = line_buffered
        self.fsync_interval = fsync_interval if fsync_interval and fsync_interval > 0 else None
        self._last_fsync = time.monotonic()
        self._fh = None
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(output_file, "a", encoding="utf-8", buffering=1 if line_buffered else -1)

    def write_event(self, event: Dict[str, Any]) -> None:
        if "event_id" not in event:
            event["event_id"] = deterministic_event_id(event)
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)

        sys.stdout.write(line + "\n")
        if self.line_buffered:
            sys.stdout.flush()

        if self._fh:
            self._fh.write(line + "\n")
            if self.line_buffered:
                self._fh.flush()
            if self.fsync_interval is not None:
                now = time.monotonic()
                if (now - self._last_fsync) >= self.fsync_interval:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                    self._last_fsync = now

    def close(self) -> None:
        if self._fh:
            self._fh.flush()
            if self.fsync_interval is not None:
                os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None


async def run_dummy_service(args: argparse.Namespace, service: str) -> None:
    writer = JsonlWriter(
        output_file=args.output_file,
        line_buffered=getattr(args, "output_line_buffered", False),
        fsync_interval=getattr(args, "jsonl_fsync_interval", None),
    )
    stop = asyncio.Event()

    def _stop(*_: Any) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    writer.write_event(
        {
            "timestamp": utc_now_iso(),
            "service": service,
            "event_type": "service_start",
            "bind_host": args.bind_host,
            "port": args.port,
        }
    )

    while not stop.is_set():
        await asyncio.sleep(1)

    writer.write_event(
        {
            "timestamp": utc_now_iso(),
            "service": service,
            "event_type": "service_stop",
        }
    )
    writer.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--bind-host", default="0.0.0.0", help="Host/interface to bind")
        p.add_argument("--port", type=int, required=True, help="Port to listen on")
        p.add_argument("--output-file", default=None, help="Write JSONL events to file")
        p.add_argument(
            "--output-line-buffered",
            action="store_true",
            help="Flush each JSONL line immediately (stdout and file)",
        )
        p.add_argument(
            "--jsonl-fsync-interval",
            type=float,
            default=None,
            help=(
                "Periodically fsync JSONL output file every N seconds for durability; "
                "disabled by default"
            ),
        )

    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        c = sub.add_parser(cmd)
        add_common(c)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run-ssh":
        asyncio.run(run_dummy_service(args, "ssh"))
    elif args.command == "run-http":
        asyncio.run(run_dummy_service(args, "http"))
    elif args.command == "run-api":
        asyncio.run(run_dummy_service(args, "api"))
    elif args.command == "run-ftp":
        asyncio.run(run_dummy_service(args, "ftp"))
    elif args.command == "run-rdp":
        asyncio.run(run_dummy_service(args, "rdp"))
    else:
        parser.error("Unknown command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
