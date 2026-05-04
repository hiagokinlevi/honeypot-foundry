from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys
from typing import Any, Awaitable, Callable, Optional

# NOTE:
# This file intentionally keeps imports local in command handlers where possible
# to avoid side effects for unrelated commands.


class _MaxEventsController:
    """Shared emitted-event counter with graceful shutdown trigger.

    This is process-wide for a single CLI invocation and is intended to be
    incremented in the common event write/forward path.
    """

    def __init__(self, max_events: Optional[int]) -> None:
        self.max_events = max_events if (max_events is not None and max_events > 0) else None
        self._count = 0
        self._shutdown_requested = False
        self._shutdown_event: asyncio.Event = asyncio.Event()

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested

    @property
    def emitted_count(self) -> int:
        return self._count

    def on_event_emitted(self) -> None:
        if self.max_events is None or self._shutdown_requested:
            return
        self._count += 1
        if self._count >= self.max_events:
            self._shutdown_requested = True
            self._shutdown_event.set()

    async def wait_for_shutdown(self) -> None:
        await self._shutdown_event.wait()


async def _run_with_max_events(
    runner: Callable[[argparse.Namespace], Awaitable[None]],
    args: argparse.Namespace,
) -> int:
    controller = _MaxEventsController(args.max_events)

    # Expose controller for downstream shared event path integration.
    # Existing components can read args._max_events_controller and call
    # on_event_emitted() from the common writer/forwarder path.
    setattr(args, "_max_events_controller", controller)

    stop_event = asyncio.Event()

    def _handle_signal(*_: Any) -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _handle_signal)

    runner_task = asyncio.create_task(runner(args))
    max_task = asyncio.create_task(controller.wait_for_shutdown()) if controller.max_events else None
    stop_task = asyncio.create_task(stop_event.wait())

    wait_set = {runner_task, stop_task}
    if max_task:
        wait_set.add(max_task)

    done, pending = await asyncio.wait(wait_set, return_when=asyncio.FIRST_COMPLETED)

    # If max-events threshold reached first, gracefully cancel runner.
    if max_task and max_task in done and not runner_task.done():
        runner_task.cancel()

    if stop_task in done and not runner_task.done():
        runner_task.cancel()

    for t in pending:
        t.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.gather(*pending, return_exceptions=True)

    try:
        await runner_task
    except asyncio.CancelledError:
        # Expected for bounded runs and signal-based stops.
        pass

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_run_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--bind-host", default="0.0.0.0")
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--output-file", default=None)
        p.add_argument(
            "--max-events",
            type=int,
            default=None,
            help="Cleanly exit after emitting N telemetry events.",
        )

    run_ssh = sub.add_parser("run-ssh")
    _add_run_common(run_ssh)

    run_http = sub.add_parser("run-http")
    _add_run_common(run_http)

    run_api = sub.add_parser("run-api")
    _add_run_common(run_api)

    run_ftp = sub.add_parser("run-ftp")
    _add_run_common(run_ftp)

    run_rdp = sub.add_parser("run-rdp")
    _add_run_common(run_rdp)

    return parser


async def _dispatch(args: argparse.Namespace) -> int:
    # Local imports to keep startup lean.
    if args.command == "run-ssh":
        from cli.run_ssh import run as runner
    elif args.command == "run-http":
        from cli.run_http import run as runner
    elif args.command == "run-api":
        from cli.run_api import run as runner
    elif args.command == "run-ftp":
        from cli.run_ftp import run as runner
    elif args.command == "run-rdp":
        from cli.run_rdp import run as runner
    else:
        raise SystemExit(f"Unknown command: {args.command}")

    return await _run_with_max_events(runner, args)


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(_dispatch(args))


if __name__ == "__main__":
    sys.exit(main())
