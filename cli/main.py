"""
Observation server CLI.

Commands:
  run-ssh      Start the SSH observation server
  run-http     Start the HTTP observation server
  run-api      Start the API observation server
  run-ftp      Start the FTP observation server
  run-rdp      Start the RDP banner observation server
  show-helm    Print Helm chart usage guidance for Kubernetes deployment
  healthcheck  Verify required dependencies are available
"""
import asyncio
from pathlib import Path

import click

from collectors.transports import (
    CEFSyslogTransport,
    ElasticBulkTransport,
    EventTransport,
    SplunkHECTransport,
)

VALID_PORT = click.IntRange(1, 65535)


@click.group()
def cli() -> None:
    """Honeypot Foundry — decoy server observation toolkit."""


def siem_options(func):
    options = [
        click.option("--cef-syslog-protocol", type=click.Choice(["udp", "tcp"]), default="udp", show_default=True),
        click.option("--cef-syslog-port", default=514, show_default=True, type=VALID_PORT),
        click.option("--cef-syslog-host", default=None, help="Forward CEF/syslog events to the given host"),
        click.option("--elastic-password", default=None, help="Elastic/OpenSearch password"),
        click.option("--elastic-username", default=None, help="Elastic/OpenSearch username"),
        click.option("--elastic-index", default="honeypot-events", show_default=True),
        click.option("--elastic-url", default=None, help="Elastic/OpenSearch bulk API endpoint"),
        click.option("--splunk-source", default="honeypot-foundry", show_default=True),
        click.option("--splunk-index", default="honeypot", show_default=True),
        click.option("--splunk-hec-token", default=None, help="Splunk HEC token"),
        click.option("--splunk-hec-url", default=None, help="Splunk HEC endpoint URL"),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def build_transports(
    *,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> list[EventTransport]:
    transports: list[EventTransport] = []

    if splunk_hec_url:
        if not splunk_hec_token:
            raise click.ClickException("--splunk-hec-token is required when --splunk-hec-url is set.")
        try:
            transports.append(
                SplunkHECTransport(
                    endpoint_url=splunk_hec_url,
                    token=splunk_hec_token,
                    index=splunk_index,
                    source=splunk_source,
                )
            )
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    elif splunk_hec_token:
        raise click.ClickException("--splunk-hec-url is required when --splunk-hec-token is set.")

    if elastic_url:
        if bool(elastic_username) != bool(elastic_password):
            raise click.ClickException(
                "--elastic-username and --elastic-password must be provided together."
            )
        try:
            transports.append(
                ElasticBulkTransport(
                    endpoint_url=elastic_url,
                    index=elastic_index,
                    username=elastic_username,
                    password=elastic_password,
                )
            )
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    elif elastic_username or elastic_password:
        raise click.ClickException("--elastic-url is required when Elastic credentials are set.")

    if cef_syslog_host:
        try:
            transports.append(
                CEFSyslogTransport(
                    host=cef_syslog_host,
                    port=cef_syslog_port,
                    protocol=cef_syslog_protocol,
                )
            )
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc

    return transports


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2222, show_default=True, type=VALID_PORT)
@click.option("--host-key", default="./hostkey", show_default=True)
@click.option("--output-file", default=None, help="JSONL output file path")
@siem_options
def run_ssh(
    host: str,
    port: int,
    host_key: str,
    output_file: str | None,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> None:
    """Start the SSH observation server (always denies authentication)."""
    from collectors.writer import EventWriter
    from honeypots.ssh.server import start_ssh_observation_server

    out_path = Path(output_file) if output_file else None
    transports = build_transports(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_index=splunk_index,
        splunk_source=splunk_source,
        elastic_url=elastic_url,
        elastic_index=elastic_index,
        elastic_username=elastic_username,
        elastic_password=elastic_password,
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
    )
    with EventWriter(out_path, transports=transports) as writer:
        async def _run() -> None:
            server = await start_ssh_observation_server(host, port, host_key, writer.write)
            click.echo(f"SSH observation server listening on {host}:{port}")
            async with server:
                await server.wait_closed()

        asyncio.run(_run())


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8080, show_default=True, type=VALID_PORT)
@click.option("--output-file", default=None, help="JSONL output file path")
@siem_options
def run_http(
    host: str,
    port: int,
    output_file: str | None,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> None:
    """Start the HTTP observation server."""
    import uvicorn
    from collectors.writer import EventWriter
    from honeypots.http.server import build_http_app

    out_path = Path(output_file) if output_file else None
    transports = build_transports(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_index=splunk_index,
        splunk_source=splunk_source,
        elastic_url=elastic_url,
        elastic_index=elastic_index,
        elastic_username=elastic_username,
        elastic_password=elastic_password,
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
    )
    with EventWriter(out_path, transports=transports) as writer:
        app = build_http_app(writer.write)
        uvicorn.run(app, host=host, port=port)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, show_default=True, type=VALID_PORT)
@click.option("--output-file", default=None, help="JSONL output file path")
@siem_options
def run_api(
    host: str,
    port: int,
    output_file: str | None,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> None:
    """Start the API observation server."""
    import uvicorn
    from collectors.writer import EventWriter
    from honeypots.api.server import build_api_decoy

    out_path = Path(output_file) if output_file else None
    transports = build_transports(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_index=splunk_index,
        splunk_source=splunk_source,
        elastic_url=elastic_url,
        elastic_index=elastic_index,
        elastic_username=elastic_username,
        elastic_password=elastic_password,
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
    )
    with EventWriter(out_path, transports=transports) as writer:
        app = build_api_decoy(writer.write)
        uvicorn.run(app, host=host, port=port)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2121, show_default=True, type=VALID_PORT)
@click.option("--banner", default="Microsoft FTP Service", show_default=True)
@click.option("--response-delay-ms", default=0, show_default=True, type=int)
@click.option("--output-file", default=None, help="JSONL output file path")
@siem_options
def run_ftp(
    host: str,
    port: int,
    banner: str,
    response_delay_ms: int,
    output_file: str | None,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> None:
    """Start the FTP observation server."""
    from collectors.writer import EventWriter
    from honeypots.ftp.server import start_ftp_observation_server

    out_path = Path(output_file) if output_file else None
    transports = build_transports(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_index=splunk_index,
        splunk_source=splunk_source,
        elastic_url=elastic_url,
        elastic_index=elastic_index,
        elastic_username=elastic_username,
        elastic_password=elastic_password,
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
    )
    with EventWriter(out_path, transports=transports) as writer:
        async def _run() -> None:
            server = await start_ftp_observation_server(
                host,
                port,
                writer.write,
                banner=banner,
                response_delay_ms=response_delay_ms,
            )
            click.echo(f"FTP observation server listening on {host}:{port}")
            async with server:
                await server.wait_closed()

        asyncio.run(_run())


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=3389, show_default=True, type=VALID_PORT)
@click.option("--read-timeout-s", default=2.0, show_default=True, type=float)
@click.option("--response-delay-ms", default=0, show_default=True, type=int)
@click.option("--output-file", default=None, help="JSONL output file path")
@siem_options
def run_rdp(
    host: str,
    port: int,
    read_timeout_s: float,
    response_delay_ms: int,
    output_file: str | None,
    splunk_hec_url: str | None,
    splunk_hec_token: str | None,
    splunk_index: str,
    splunk_source: str,
    elastic_url: str | None,
    elastic_index: str,
    elastic_username: str | None,
    elastic_password: str | None,
    cef_syslog_host: str | None,
    cef_syslog_port: int,
    cef_syslog_protocol: str,
) -> None:
    """Start the RDP banner observation server."""
    from collectors.writer import EventWriter
    from honeypots.rdp.server import start_rdp_banner_observer

    out_path = Path(output_file) if output_file else None
    transports = build_transports(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_index=splunk_index,
        splunk_source=splunk_source,
        elastic_url=elastic_url,
        elastic_index=elastic_index,
        elastic_username=elastic_username,
        elastic_password=elastic_password,
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
    )
    with EventWriter(out_path, transports=transports) as writer:
        async def _run() -> None:
            server = await start_rdp_banner_observer(
                host,
                port,
                writer.write,
                read_timeout_s=read_timeout_s,
                response_delay_ms=response_delay_ms,
            )
            click.echo(f"RDP banner observation server listening on {host}:{port}")
            async with server:
                await server.wait_closed()

        asyncio.run(_run())


@cli.command()
def show_helm() -> None:
    """Show Helm chart path and quick deployment commands."""
    chart_dir = Path(__file__).resolve().parent.parent / "helm" / "honeypot-foundry"
    click.echo(f"Helm chart: {chart_dir}")
    click.echo("")
    click.echo("Quickstart:")
    click.echo("  helm upgrade --install honeypot-foundry \\")
    click.echo(f"    {chart_dir} \\")
    click.echo("    --namespace honeypot-foundry --create-namespace")
    click.echo("")
    click.echo("Optional overrides:")
    click.echo("  --set services.ssh.enabled=true")
    click.echo("  --set services.http.enabled=true")
    click.echo("  --set services.api.enabled=true")
    click.echo("  --set services.ftp.enabled=true")
    click.echo("  --set services.rdp.enabled=true")
    click.echo("  --set autoscaling.enabled=true")
    click.echo("  --set podDisruptionBudget.enabled=true")


@cli.command()
def healthcheck() -> None:
    """Verify that required dependencies are importable."""
    try:
        import asyncssh
        import fastapi
        import structlog
        click.echo("All dependencies available.")
    except ImportError as e:
        click.echo(f"Missing dependency: {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
