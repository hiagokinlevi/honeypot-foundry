from __future__ import annotations

import argparse
import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict

from honeypots.api_honeypot import run_api_honeypot
from honeypots.ftp_honeypot import run_ftp_honeypot
from honeypots.http_honeypot import run_http_honeypot
from honeypots.rdp_honeypot import run_rdp_honeypot
from honeypots.ssh_honeypot import run_ssh_honeypot


def _configure_event_logger(
    output_file: str | None,
    output_max_bytes: int | None = None,
    output_backups: int | None = None,
) -> logging.Logger:
    logger = logging.getLogger("honeypot.events")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        max_bytes = int(output_max_bytes or 0)
        backups = int(output_backups or 0)
        if max_bytes > 0:
            file_handler = RotatingFileHandler(
                output_file,
                maxBytes=max_bytes,
                backupCount=max(0, backups),
                encoding="utf-8",
            )
        else:
            file_handler = logging.FileHandler(output_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(file_handler)

    return logger


def _emit_event(logger: logging.Logger, event: Dict[str, Any]) -> None:
    logger.info(json.dumps(event, separators=(",", ":"), ensure_ascii=False))


def _add_output_rotation_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-max-bytes",
        type=int,
        default=None,
        help="Rotate local JSONL output file when it exceeds this size in bytes.",
    )
    parser.add_argument(
        "--output-backups",
        type=int,
        default=None,
        help="Number of rotated JSONL backup files to retain (used with --output-max-bytes).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ssh = subparsers.add_parser("run-ssh")
    ssh.add_argument("--port", type=int, default=2222)
    ssh.add_argument("--output-file", default=None)
    _add_output_rotation_flags(ssh)

    http = subparsers.add_parser("run-http")
    http.add_argument("--port", type=int, default=8080)
    http.add_argument("--output-file", default=None)
    _add_output_rotation_flags(http)

    api = subparsers.add_parser("run-api")
    api.add_argument("--port", type=int, default=8000)
    api.add_argument("--output-file", default=None)
    _add_output_rotation_flags(api)

    ftp = subparsers.add_parser("run-ftp")
    ftp.add_argument("--port", type=int, default=2121)
    ftp.add_argument("--banner", default="Microsoft FTP Service")
    ftp.add_argument("--output-file", default=None)
    _add_output_rotation_flags(ftp)

    rdp = subparsers.add_parser("run-rdp")
    rdp.add_argument("--port", type=int, default=3389)
    rdp.add_argument("--output-file", default=None)
    _add_output_rotation_flags(rdp)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logger = _configure_event_logger(
        getattr(args, "output_file", None),
        getattr(args, "output_max_bytes", None),
        getattr(args, "output_backups", None),
    )

    if args.command == "run-ssh":
        run_ssh_honeypot(port=args.port, emit=lambda e: _emit_event(logger, e))
    elif args.command == "run-http":
        run_http_honeypot(port=args.port, emit=lambda e: _emit_event(logger, e))
    elif args.command == "run-api":
        run_api_honeypot(port=args.port, emit=lambda e: _emit_event(logger, e))
    elif args.command == "run-ftp":
        run_ftp_honeypot(port=args.port, banner=args.banner, emit=lambda e: _emit_event(logger, e))
    elif args.command == "run-rdp":
        run_rdp_honeypot(port=args.port, emit=lambda e: _emit_event(logger, e))


if __name__ == "__main__":
    main()
