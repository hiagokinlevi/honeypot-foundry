from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import typer

from collectors.forwarder import EventForwarder
from honeypots.api_honeypot import run_api_honeypot
from honeypots.ftp_honeypot import run_ftp_honeypot
from honeypots.http_honeypot import run_http_honeypot
from honeypots.rdp_honeypot import run_rdp_honeypot
from honeypots.ssh_honeypot import run_ssh_honeypot

app = typer.Typer(help="Defensive honeypot toolkit CLI")


@app.callback()
def main(
    instance_id: Optional[str] = typer.Option(
        None,
        "--instance-id",
        help="Stable honeypot instance identifier tagged on all emitted events. Falls back to HONEYPOT_INSTANCE_ID env var.",
    ),
    bind_host: str = typer.Option(
        "0.0.0.0",
        "--bind-host",
        help="Listener bind address for honeypot services (e.g. 0.0.0.0 or 127.0.0.1).",
    ),
) -> None:
    ctx = typer.get_current_context()
    ctx.obj = ctx.obj or {}
    ctx.obj["instance_id"] = instance_id or os.getenv("HONEYPOT_INSTANCE_ID")
    ctx.obj["bind_host"] = bind_host


def _build_forwarder(
    splunk_url: Optional[str],
    splunk_token: Optional[str],
    elastic_url: Optional[str],
    sentinel_host: Optional[str],
    sentinel_port: int,
) -> Optional[EventForwarder]:
    if not any([splunk_url and splunk_token, elastic_url, sentinel_host]):
        return None
    return EventForwarder(
        splunk_hec_url=splunk_url,
        splunk_hec_token=splunk_token,
        elastic_url=elastic_url,
        sentinel_host=sentinel_host,
        sentinel_port=sentinel_port,
    )


def _run_heartbeat(stop_event: threading.Event, interval_seconds: int) -> None:
    while not stop_event.is_set():
        payload: Dict[str, Any] = {
            "type": "honeypot_heartbeat",
            "status": "alive",
            "ts": int(time.time()),
        }
        print(json.dumps(payload), flush=True)
        stop_event.wait(interval_seconds)


def _with_heartbeat(run_fn, heartbeat_interval: int = 30) -> None:
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_heartbeat,
        args=(stop_event, heartbeat_interval),
        daemon=True,
    )
    thread.start()

    def _shutdown(*_: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        run_fn()
    finally:
        stop_event.set()
        thread.join(timeout=1)


@app.command("run-ssh")
def run_ssh(
    port: int = typer.Option(2222, "--port", help="SSH honeypot port"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", help="JSONL output file"),
    rotate_max_bytes: int = typer.Option(
        0,
        "--rotate-max-bytes",
        help="Rotate JSONL output file when it reaches this size in bytes (0 disables rotation).",
    ),
    rotate_backup_count: int = typer.Option(
        3,
        "--rotate-backup-count",
        help="Number of rotated JSONL backup files to keep.",
    ),
    heartbeat_interval: int = typer.Option(
        30,
        "--heartbeat-interval",
        help="Seconds between stdout heartbeat metric lines.",
    ),
) -> None:
    ctx = typer.get_current_context()
    bind_host = ctx.obj.get("bind_host", "0.0.0.0")
    instance_id = ctx.obj.get("instance_id")

    _with_heartbeat(
        lambda: run_ssh_honeypot(
            host=bind_host,
            port=port,
            output_file=output_file,
            rotate_max_bytes=rotate_max_bytes,
            rotate_backup_count=rotate_backup_count,
            instance_id=instance_id,
        ),
        heartbeat_interval=heartbeat_interval,
    )


@app.command("run-http")
def run_http(
    port: int = typer.Option(8080, "--port", help="HTTP honeypot port"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", help="JSONL output file"),
    rotate_max_bytes: int = typer.Option(
        0,
        "--rotate-max-bytes",
        help="Rotate JSONL output file when it reaches this size in bytes (0 disables rotation).",
    ),
    rotate_backup_count: int = typer.Option(
        3,
        "--rotate-backup-count",
        help="Number of rotated JSONL backup files to keep.",
    ),
    splunk_url: Optional[str] = typer.Option(None, "--splunk-url", help="Splunk HEC URL"),
    splunk_token: Optional[str] = typer.Option(None, "--splunk-token", help="Splunk HEC token"),
    elastic_url: Optional[str] = typer.Option(None, "--elastic-url", help="Elastic bulk API URL"),
    sentinel_host: Optional[str] = typer.Option(None, "--sentinel-host", help="Syslog host for Sentinel CEF"),
    sentinel_port: int = typer.Option(514, "--sentinel-port", help="Syslog port for Sentinel CEF"),
    heartbeat_interval: int = typer.Option(
        30,
        "--heartbeat-interval",
        help="Seconds between stdout heartbeat metric lines.",
    ),
) -> None:
    ctx = typer.get_current_context()
    bind_host = ctx.obj.get("bind_host", "0.0.0.0")
    instance_id = ctx.obj.get("instance_id")
    forwarder = _build_forwarder(splunk_url, splunk_token, elastic_url, sentinel_host, sentinel_port)

    _with_heartbeat(
        lambda: run_http_honeypot(
            host=bind_host,
            port=port,
            output_file=output_file,
            rotate_max_bytes=rotate_max_bytes,
            rotate_backup_count=rotate_backup_count,
            forwarder=forwarder,
            instance_id=instance_id,
        ),
        heartbeat_interval=heartbeat_interval,
    )


@app.command("run-api")
def run_api(
    port: int = typer.Option(8000, "--port", help="API honeypot port"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", help="JSONL output file"),
    rotate_max_bytes: int = typer.Option(
        0,
        "--rotate-max-bytes",
        help="Rotate JSONL output file when it reaches this size in bytes (0 disables rotation).",
    ),
    rotate_backup_count: int = typer.Option(
        3,
        "--rotate-backup-count",
        help="Number of rotated JSONL backup files to keep.",
    ),
    heartbeat_interval: int = typer.Option(
        30,
        "--heartbeat-interval",
        help="Seconds between stdout heartbeat metric lines.",
    ),
) -> None:
    ctx = typer.get_current_context()
    bind_host = ctx.obj.get("bind_host", "0.0.0.0")
    instance_id = ctx.obj.get("instance_id")

    _with_heartbeat(
        lambda: run_api_honeypot(
            host=bind_host,
            port=port,
            output_file=output_file,
            rotate_max_bytes=rotate_max_bytes,
            rotate_backup_count=rotate_backup_count,
            instance_id=instance_id,
        ),
        heartbeat_interval=heartbeat_interval,
    )


@app.command("run-ftp")
def run_ftp(
    port: int = typer.Option(2121, "--port", help="FTP honeypot port"),
    banner: str = typer.Option("Microsoft FTP Service", "--banner", help="FTP banner string"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", help="JSONL output file"),
    rotate_max_bytes: int = typer.Option(
        0,
        "--rotate-max-bytes",
        help="Rotate JSONL output file when it reaches this size in bytes (0 disables rotation).",
    ),
    rotate_backup_count: int = typer.Option(
        3,
        "--rotate-backup-count",
        help="Number of rotated JSONL backup files to keep.",
    ),
    heartbeat_interval: int = typer.Option(
        30,
        "--heartbeat-interval",
        help="Seconds between stdout heartbeat metric lines.",
    ),
) -> None:
    ctx = typer.get_current_context()
    bind_host = ctx.obj.get("bind_host", "0.0.0.0")
    instance_id = ctx.obj.get("instance_id")

    _with_heartbeat(
        lambda: run_ftp_honeypot(
            host=bind_host,
            port=port,
            banner=banner,
            output_file=output_file,
            rotate_max_bytes=rotate_max_bytes,
            rotate_backup_count=rotate_backup_count,
            instance_id=instance_id,
        ),
        heartbeat_interval=heartbeat_interval,
    )


@app.command("run-rdp")
def run_rdp(
    port: int = typer.Option(3389, "--port", help="RDP honeypot port"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", help="JSONL output file"),
    rotate_max_bytes: int = typer.Option(
        0,
        "--rotate-max-bytes",
        help="Rotate JSONL output file when it reaches this size in bytes (0 disables rotation).",
    ),
    rotate_backup_count: int = typer.Option(
        3,
        "--rotate-backup-count",
        help="Number of rotated JSONL backup files to keep.",
    ),
    heartbeat_interval: int = typer.Option(
        30,
        "--heartbeat-interval",
        help="Seconds between stdout heartbeat metric lines.",
    ),
) -> None:
    ctx = typer.get_current_context()
    bind_host = ctx.obj.get("bind_host", "0.0.0.0")
    instance_id = ctx.obj.get("instance_id")

    _with_heartbeat(
        lambda: run_rdp_honeypot(
            host=bind_host,
            port=port,
            output_file=output_file,
            rotate_max_bytes=rotate_max_bytes,
            rotate_backup_count=rotate_backup_count,
            instance_id=instance_id,
        ),
        heartbeat_interval=heartbeat_interval,
    )


@app.command("show-helm")
def show_helm() -> None:
    root = Path(__file__).resolve().parent
    chart_path = root / "helm" / "honeypot-foundry"
    typer.echo(str(chart_path))
    typer.echo("Use your preferred Helm workflow to deploy the chart.")


if __name__ == "__main__":
    app()
