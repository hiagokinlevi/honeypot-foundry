#!/usr/bin/env python3
"""CLI entrypoint for honeypot-foundry."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any, Callable


class JsonlOutput:
    """Simple JSONL output helper used by CLI commands."""

    def __init__(self, output_file: str | None = None) -> None:
        self._path = Path(output_file) if output_file else None
        self._fh = None
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self._path.open("a", encoding="utf-8")

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        print(line, flush=True)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


async def _heartbeat_loop(
    output: JsonlOutput,
    service_name: str,
    start_time: float,
    interval_seconds: int,
    events_counter: Callable[[], int],
    stop_evt: asyncio.Event,
) -> None:
    while not stop_evt.is_set():
        try:
            await asyncio.wait_for(stop_evt.wait(), timeout=interval_seconds)
            break
        except asyncio.TimeoutError:
            output.write(
                {
                    "event_type": "heartbeat",
                    "service": service_name,
                    "uptime_seconds": int(time.time() - start_time),
                    "events_processed": int(events_counter()),
                }
            )


async def _run_with_heartbeat(
    args: argparse.Namespace,
    service_name: str,
    runner: Callable[[argparse.Namespace, Callable[[dict[str, Any]], None], asyncio.Event], asyncio.Future],
) -> int:
    output = JsonlOutput(getattr(args, "output_file", None))
    start_time = time.time()
    stop_evt = asyncio.Event()
    events_processed = 0

    def emit(event: dict[str, Any]) -> None:
        nonlocal events_processed
        events_processed += 1
        output.write(event)

    loop = asyncio.get_running_loop()

    def _shutdown(*_: Any) -> None:
        stop_evt.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            pass

    hb_task = None
    hb_seconds = getattr(args, "heartbeat_seconds", 0) or 0
    if hb_seconds > 0:
        hb_task = asyncio.create_task(
            _heartbeat_loop(
                output=output,
                service_name=service_name,
                start_time=start_time,
                interval_seconds=hb_seconds,
                events_counter=lambda: events_processed,
                stop_evt=stop_evt,
            )
        )

    try:
        await runner(args, emit, stop_evt)
    finally:
        stop_evt.set()
        if hb_task:
            await hb_task
        output.close()
    return 0


async def _dummy_runner(
    args: argparse.Namespace, emit: Callable[[dict[str, Any]], None], stop_evt: asyncio.Event
) -> None:
    emit({"event_type": "service_start", "service": args.command})
    await stop_evt.wait()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--output-file", default=None)
        p.add_argument(
            "--heartbeat-seconds",
            type=int,
            default=0,
            help="Emit compact heartbeat JSON event every N seconds (disabled by default).",
        )

    p_ssh = sub.add_parser("run-ssh")
    add_common(p_ssh)

    p_http = sub.add_parser("run-http")
    add_common(p_http)

    p_api = sub.add_parser("run-api")
    add_common(p_api)

    p_ftp = sub.add_parser("run-ftp")
    add_common(p_ftp)

    p_rdp = sub.add_parser("run-rdp")
    add_common(p_rdp)

    return parser


async def _dispatch(args: argparse.Namespace) -> int:
    if args.command in {"run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"}:
        return await _run_with_heartbeat(args, args.command.replace("run-", ""), _dummy_runner)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
