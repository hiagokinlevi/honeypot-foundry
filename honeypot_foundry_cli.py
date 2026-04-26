from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _validate_output_path_writable(path_value: str) -> str | None:
    if not path_value:
        return "output file path is required"

    p = Path(path_value)
    parent = p.parent if p.parent != Path("") else Path(".")

    if not parent.exists():
        return f"output directory does not exist: {parent}"
    if not parent.is_dir():
        return f"output parent is not a directory: {parent}"
    if not os.access(parent, os.W_OK):
        return f"output directory is not writable: {parent}"

    if p.exists() and not os.access(p, os.W_OK):
        return f"output file is not writable: {p}"

    return None


def _validate_siem_combo(args: argparse.Namespace) -> str | None:
    endpoint = getattr(args, "siem_endpoint", None)
    token = getattr(args, "siem_token", None)

    if (endpoint and not token) or (token and not endpoint):
        return "SIEM configuration requires both --siem-endpoint and --siem-token"
    return None


def _validate_port(port: int | None) -> str | None:
    if port is None:
        return "--port is required"
    if not (1 <= int(port) <= 65535):
        return f"port out of range: {port} (expected 1-65535)"
    return None


def _validate_schema_timestamp(args: argparse.Namespace) -> str | None:
    schema = getattr(args, "schema_version", None)
    ts_mode = getattr(args, "timestamp_mode", None)
    if schema and ts_mode:
        if schema == "v1" and ts_mode == "epoch_ms":
            return "schema v1 is incompatible with --timestamp-mode epoch_ms"
    return None


def run_preflight(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    # Only run-command preflight checks.
    if not hasattr(args, "port"):
        return errors

    for check in (
        _validate_port(getattr(args, "port", None)),
        _validate_output_path_writable(getattr(args, "output_file", "")),
        _validate_siem_combo(args),
        _validate_schema_timestamp(args),
    ):
        if check:
            errors.append(check)

    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--instance-id", default=None)
    parser.add_argument(
        "--dry-run-config",
        action="store_true",
        help="validate runtime configuration and exit without starting listeners",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_run_cmd(name: str) -> None:
        p = subparsers.add_parser(name)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--output-file", dest="output_file", required=True)
        p.add_argument("--siem-endpoint", dest="siem_endpoint")
        p.add_argument("--siem-token", dest="siem_token")
        p.add_argument("--schema-version", dest="schema_version", default="v1")
        p.add_argument("--timestamp-mode", dest="timestamp_mode", default="iso8601")

    add_run_cmd("run-ssh")
    add_run_cmd("run-http")
    add_run_cmd("run-api")
    add_run_cmd("run-ftp")
    add_run_cmd("run-rdp")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dry_run_config:
        errors = run_preflight(args)
        if errors:
            print("[preflight] FAIL")
            for e in errors:
                print(f" - {e}")
            return 2
        print("[preflight] PASS")
        return 0

    # Existing runtime startup wiring would continue here.
    # Kept intentionally minimal for this incremental task.
    print(f"starting {args.command} on {args.bind_host}:{args.port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
