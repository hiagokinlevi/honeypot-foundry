import argparse
import asyncio
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


DEFAULT_OUTPUT_FILE_PERMISSIONS = "600"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_output_file_permissions(value: str) -> int:
    v = value.strip()
    if len(v) not in (3, 4):
        raise argparse.ArgumentTypeError("must be octal like 600 or 0640")
    if any(ch not in "01234567" for ch in v):
        raise argparse.ArgumentTypeError("must contain only octal digits 0-7")
    mode = int(v, 8)
    if mode > 0o7777:
        raise argparse.ArgumentTypeError("octal mode out of range")
    return mode


class JsonlWriter:
    def __init__(
        self,
        output_file: Optional[str] = None,
        line_buffered: bool = False,
        rotate_max_bytes: int = 0,
        output_file_permissions: int = 0o600,
    ) -> None:
        self.output_file = output_file
        self.line_buffered = line_buffered
        self.rotate_max_bytes = rotate_max_bytes
        self.output_file_permissions = output_file_permissions
        self._fh = None
        if self.output_file:
            self._open_file(append=True)

    def _emit_permissions_warning_event(self, path: str, error: Exception) -> None:
        evt = {
            "event_type": "output_file_permissions_warning",
            "timestamp": _utc_now_iso(),
            "path": path,
            "requested_mode": oct(self.output_file_permissions),
            "error": str(error),
        }
        sys.stderr.write(json.dumps(evt) + "\n")
        sys.stderr.flush()

    def _apply_permissions(self, path: str) -> None:
        try:
            os.chmod(path, self.output_file_permissions)
        except Exception as exc:  # pragma: no cover
            self._emit_permissions_warning_event(path, exc)

    def _open_file(self, append: bool = True) -> None:
        mode = "a" if append else "w"
        existed = os.path.exists(self.output_file)
        self._fh = open(self.output_file, mode, buffering=1 if self.line_buffered else -1, encoding="utf-8")
        if not existed:
            self._apply_permissions(self.output_file)

    def _should_rotate(self, line_len: int) -> bool:
        if not self._fh or not self.rotate_max_bytes or self.rotate_max_bytes <= 0:
            return False
        try:
            current = self._fh.tell()
        except Exception:
            return False
        return (current + line_len) > self.rotate_max_bytes

    def _rotate(self) -> None:
        if not self._fh or not self.output_file:
            return
        self._fh.close()
        rotated = f"{self.output_file}.{int(time.time())}"
        os.replace(self.output_file, rotated)
        self._open_file(append=False)

    def write(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        sys.stdout.write(line)
        if self.line_buffered:
            sys.stdout.flush()
        if self._fh:
            if self._should_rotate(len(line.encode("utf-8"))):
                self._rotate()
            self._fh.write(line)
            if self.line_buffered:
                self._fh.flush()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_run(name: str) -> None:
        p = sub.add_parser(name)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--bind-host", default="0.0.0.0")
        p.add_argument("--output-file")
        p.add_argument("--output-line-buffered", action="store_true")
        p.add_argument("--output-rotate-max-bytes", type=int, default=0)
        p.add_argument(
            "--output-file-permissions",
            type=_parse_output_file_permissions,
            default=_parse_output_file_permissions(DEFAULT_OUTPUT_FILE_PERMISSIONS),
            help="Octal file mode for created/rotated JSONL files (default: 600)",
        )

    for cmd in ("run-ssh", "run-http", "run-api", "run-ftp", "run-rdp"):
        add_run(cmd)

    return parser


async def _run(args: argparse.Namespace) -> None:
    writer = JsonlWriter(
        output_file=args.output_file,
        line_buffered=args.output_line_buffered,
        rotate_max_bytes=args.output_rotate_max_bytes,
        output_file_permissions=args.output_file_permissions,
    )
    writer.write(
        {
            "event_type": "startup",
            "timestamp": _utc_now_iso(),
            "service": args.command,
            "bind_host": args.bind_host,
            "port": args.port,
            "instance_id": hashlib.sha256(f"{socket.gethostname()}:{args.port}".encode()).hexdigest()[:12],
        }
    )
    while True:
        await asyncio.sleep(3600)


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command.startswith("run-"):
        asyncio.run(_run(args))
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
