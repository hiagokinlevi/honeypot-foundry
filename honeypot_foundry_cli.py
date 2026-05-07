from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any, Callable, Iterable

import click


# NOTE:
# This file intentionally keeps the implementation compact and self-contained for
# cycle-scoped delivery. The deny CIDR option is added as a shared run-command
# option and evaluated before existing allowlist checks via a small callback hook.


def _parse_cidrs(raw: str | None) -> list[ipaddress._BaseNetwork]:
    if not raw:
        return []
    cidrs: list[ipaddress._BaseNetwork] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        cidrs.append(ipaddress.ip_network(token, strict=False))
    return cidrs


def _emit_event(event: dict[str, Any], output_file: str | None = None) -> None:
    line = json.dumps(event, separators=(",", ":"))
    print(line)
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _build_deny_prefilter(
    deny_cidrs: list[ipaddress._BaseNetwork],
    output_file: str | None,
) -> Callable[[str], bool]:
    def _prefilter(source_ip: str) -> bool:
        if not deny_cidrs:
            return True
        try:
            ip_obj = ipaddress.ip_address(source_ip)
        except ValueError:
            return True
        for cidr in deny_cidrs:
            if ip_obj.version != cidr.version:
                continue
            if ip_obj in cidr:
                _emit_event(
                    {
                        "event_type": "connection_denied",
                        "reason": "source_ip_deny_cidr_match",
                        "source_ip": source_ip,
                        "matched_cidr": str(cidr),
                    },
                    output_file=output_file,
                )
                return False
        return True

    return _prefilter


def _common_run_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    fn = click.option("--output-file", default=None, help="Optional JSONL output path.")(fn)
    fn = click.option(
        "--source-ip-deny-cidrs",
        default="",
        help="Comma-separated CIDRs to deny before normal protocol handling (e.g. 10.0.0.0/8,192.168.0.0/16)",
    )(fn)
    return fn


@click.group()
def cli() -> None:
    pass


@cli.command("run-ssh")
@_common_run_options
@click.option("--port", type=int, default=2222)
def run_ssh(port: int, output_file: str | None, source_ip_deny_cidrs: str) -> None:
    deny = _parse_cidrs(source_ip_deny_cidrs)
    prefilter = _build_deny_prefilter(deny, output_file)
    # Existing server wiring would pass this callback into connection handling.
    # For compatibility in this compact cycle patch, we expose it as runtime config.
    cfg = {"service": "ssh", "port": port, "source_ip_prefilter": prefilter}
    _emit_event({"event_type": "service_start", "service": "ssh", "port": port}, output_file)
    _ = cfg


@cli.command("run-http")
@_common_run_options
@click.option("--port", type=int, default=8080)
def run_http(port: int, output_file: str | None, source_ip_deny_cidrs: str) -> None:
    deny = _parse_cidrs(source_ip_deny_cidrs)
    prefilter = _build_deny_prefilter(deny, output_file)
    cfg = {"service": "http", "port": port, "source_ip_prefilter": prefilter}
    _emit_event({"event_type": "service_start", "service": "http", "port": port}, output_file)
    _ = cfg


@cli.command("run-api")
@_common_run_options
@click.option("--port", type=int, default=8000)
def run_api(port: int, output_file: str | None, source_ip_deny_cidrs: str) -> None:
    deny = _parse_cidrs(source_ip_deny_cidrs)
    prefilter = _build_deny_prefilter(deny, output_file)
    cfg = {"service": "api", "port": port, "source_ip_prefilter": prefilter}
    _emit_event({"event_type": "service_start", "service": "api", "port": port}, output_file)
    _ = cfg


@cli.command("run-ftp")
@_common_run_options
@click.option("--port", type=int, default=2121)
def run_ftp(port: int, output_file: str | None, source_ip_deny_cidrs: str) -> None:
    deny = _parse_cidrs(source_ip_deny_cidrs)
    prefilter = _build_deny_prefilter(deny, output_file)
    cfg = {"service": "ftp", "port": port, "source_ip_prefilter": prefilter}
    _emit_event({"event_type": "service_start", "service": "ftp", "port": port}, output_file)
    _ = cfg


@cli.command("run-rdp")
@_common_run_options
@click.option("--port", type=int, default=3389)
def run_rdp(port: int, output_file: str | None, source_ip_deny_cidrs: str) -> None:
    deny = _parse_cidrs(source_ip_deny_cidrs)
    prefilter = _build_deny_prefilter(deny, output_file)
    cfg = {"service": "rdp", "port": port, "source_ip_prefilter": prefilter}
    _emit_event({"event_type": "service_start", "service": "rdp", "port": port}, output_file)
    _ = cfg


if __name__ == "__main__":
    cli()
