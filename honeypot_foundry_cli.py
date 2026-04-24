from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from collectors.event_writer import EventWriter
from honeypots.api_honeypot import run_api_honeypot
from honeypots.ftp_honeypot import run_ftp_honeypot
from honeypots.http_honeypot import run_http_honeypot
from honeypots.rdp_honeypot import run_rdp_honeypot
from honeypots.ssh_honeypot import run_ssh_honeypot


DEFAULT_OUTPUT_FILE_MODE = "append"
OUTPUT_FILE_MODE_CHOICES = ("append", "overwrite")


def _resolve_instance_id(cli_value: str | None) -> str | None:
    if cli_value:
        return cli_value
    env_val = os.getenv("HONEYPOT_INSTANCE_ID")
    return env_val or None


@dataclass(slots=True)
class RuntimeConfig:
    bind_host: str
    output_file: str | None
    output_file_mode: str
    instance_id: str | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot", description="Honeypot Foundry CLI")
    parser.add_argument("--bind-host", default="0.0.0.0", help="Host/interface to bind listeners (default: 0.0.0.0)")
    parser.add_argument("--instance-id", default=None, help="Static instance_id tag for all emitted events")

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_run_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--port", type=int, required=True, help="Listening port")
        sp.add_argument("--output-file", default=None, help="Write JSONL events to file")
        sp.add_argument(
            "--output-file-mode",
            choices=OUTPUT_FILE_MODE_CHOICES,
            default=DEFAULT_OUTPUT_FILE_MODE,
            help="File mode for --output-file: append or overwrite (default: append)",
        )

    run_ssh = subparsers.add_parser("run-ssh", help="Run SSH honeypot")
    add_common_run_args(run_ssh)

    run_http = subparsers.add_parser("run-http", help="Run HTTP honeypot")
    add_common_run_args(run_http)

    run_api = subparsers.add_parser("run-api", help="Run API honeypot")
    add_common_run_args(run_api)

    run_ftp = subparsers.add_parser("run-ftp", help="Run FTP honeypot")
    run_ftp.add_argument("--banner", default="FTP Server", help="FTP banner string")
    add_common_run_args(run_ftp)

    run_rdp = subparsers.add_parser("run-rdp", help="Run RDP banner observer")
    add_common_run_args(run_rdp)

    subparsers.add_parser("healthcheck", help="Basic healthcheck")

    return parser


def _writer_from_args(args: argparse.Namespace, instance_id: str | None) -> EventWriter:
    return EventWriter(
        output_file=args.output_file,
        output_file_mode=args.output_file_mode,
        instance_id=instance_id,
    )


async def _run_with_writer(coro_factory: Callable[[EventWriter], Any], writer: EventWriter) -> None:
    stop = asyncio.Event()

    def _shutdown(*_: Any) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            pass

    task = asyncio.create_task(coro_factory(writer))
    await stop.wait()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _healthcheck() -> int:
    payload = {
        "ok": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "honeypot-foundry",
    }
    print(json.dumps(payload))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "healthcheck":
        return _healthcheck()

    instance_id = _resolve_instance_id(args.instance_id)
    writer = _writer_from_args(args, instance_id)

    if args.command == "run-ssh":
        asyncio.run(run_ssh_honeypot(host=args.bind_host, port=args.port, writer=writer))
        return 0
    if args.command == "run-http":
        asyncio.run(run_http_honeypot(host=args.bind_host, port=args.port, writer=writer))
        return 0
    if args.command == "run-api":
        asyncio.run(run_api_honeypot(host=args.bind_host, port=args.port, writer=writer))
        return 0
    if args.command == "run-ftp":
        asyncio.run(run_ftp_honeypot(host=args.bind_host, port=args.port, banner=args.banner, writer=writer))
        return 0
    if args.command == "run-rdp":
        asyncio.run(run_rdp_honeypot(host=args.bind_host, port=args.port, writer=writer))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
