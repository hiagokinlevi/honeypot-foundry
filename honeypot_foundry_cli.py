from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from cli.emitters import EventEmitter
from collectors.forwarder import Forwarder
from honeypots.api_honeypot import run_api_honeypot
from honeypots.ftp_honeypot import run_ftp_honeypot
from honeypots.http_honeypot import run_http_honeypot
from honeypots.rdp_honeypot import run_rdp_honeypot
from honeypots.ssh_honeypot import run_ssh_honeypot

DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 30


@dataclass
class RunConfig:
    port: int
    output_file: str | None
    bind_host: str
    instance_id: str | None
    heartbeat_interval_seconds: int


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("heartbeat interval must be > 0 seconds")
    return parsed


def _add_shared_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output-file", default=None)
    parser.add_argument(
        "--heartbeat-interval-seconds",
        type=_positive_int,
        default=DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        help=f"stdout heartbeat emission interval in seconds (default: {DEFAULT_HEARTBEAT_INTERVAL_SECONDS})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--instance-id", default=os.getenv("HONEYPOT_INSTANCE_ID"))

    subparsers = parser.add_subparsers(dest="command", required=True)

    ssh = subparsers.add_parser("run-ssh")
    _add_shared_run_args(ssh)

    http = subparsers.add_parser("run-http")
    _add_shared_run_args(http)

    api = subparsers.add_parser("run-api")
    _add_shared_run_args(api)

    ftp = subparsers.add_parser("run-ftp")
    _add_shared_run_args(ftp)
    ftp.add_argument("--banner", default="vsFTPd 3.0.3")

    rdp = subparsers.add_parser("run-rdp")
    _add_shared_run_args(rdp)

    subparsers.add_parser("healthcheck")

    return parser


async def _heartbeat_loop(interval_seconds: int, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        print(json.dumps({"metric": "honeypot_heartbeat", "ts": int(time.time())}), flush=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            continue


async def _run_with_heartbeat(
    run_coro_factory: Callable[[], Awaitable[Any]],
    heartbeat_interval_seconds: int,
) -> Any:
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()

    def _request_stop(*_: Any) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, _request_stop)

    heartbeat_task = asyncio.create_task(_heartbeat_loop(heartbeat_interval_seconds, stop_event))
    try:
        return await run_coro_factory()
    finally:
        stop_event.set()
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "healthcheck":
        return 0

    run_cfg = RunConfig(
        port=args.port,
        output_file=args.output_file,
        bind_host=args.bind_host,
        instance_id=args.instance_id,
        heartbeat_interval_seconds=args.heartbeat_interval_seconds,
    )

    emitter = EventEmitter(output_file=run_cfg.output_file, instance_id=run_cfg.instance_id)
    forwarder = Forwarder.from_env()

    async def _runner() -> Any:
        if args.command == "run-ssh":
            return await run_ssh_honeypot(run_cfg.bind_host, run_cfg.port, emitter, forwarder)
        if args.command == "run-http":
            return await run_http_honeypot(run_cfg.bind_host, run_cfg.port, emitter, forwarder)
        if args.command == "run-api":
            return await run_api_honeypot(run_cfg.bind_host, run_cfg.port, emitter, forwarder)
        if args.command == "run-ftp":
            return await run_ftp_honeypot(run_cfg.bind_host, run_cfg.port, args.banner, emitter, forwarder)
        if args.command == "run-rdp":
            return await run_rdp_honeypot(run_cfg.bind_host, run_cfg.port, emitter, forwarder)
        raise RuntimeError(f"unsupported command: {args.command}")

    asyncio.run(_run_with_heartbeat(_runner, run_cfg.heartbeat_interval_seconds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
