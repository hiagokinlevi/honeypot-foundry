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


@click.group()
def cli() -> None:
    """Honeypot Foundry — decoy server observation toolkit."""


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2222, show_default=True)
@click.option("--host-key", default="./hostkey", show_default=True)
@click.option("--output-file", default=None, help="JSONL output file path")
def run_ssh(host: str, port: int, host_key: str, output_file: str | None) -> None:
    """Start the SSH observation server (always denies authentication)."""
    from collectors.writer import EventWriter
    from honeypots.ssh.server import start_ssh_observation_server

    out_path = Path(output_file) if output_file else None
    with EventWriter(out_path) as writer:
        async def _run() -> None:
            server = await start_ssh_observation_server(host, port, host_key, writer.write)
            click.echo(f"SSH observation server listening on {host}:{port}")
            async with server:
                await server.wait_closed()

        asyncio.run(_run())


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--output-file", default=None, help="JSONL output file path")
def run_http(host: str, port: int, output_file: str | None) -> None:
    """Start the HTTP observation server."""
    import uvicorn
    from collectors.writer import EventWriter
    from honeypots.http.server import build_http_app

    out_path = Path(output_file) if output_file else None
    with EventWriter(out_path) as writer:
        app = build_http_app(writer.write)
        uvicorn.run(app, host=host, port=port)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, show_default=True)
@click.option("--output-file", default=None, help="JSONL output file path")
def run_api(host: str, port: int, output_file: str | None) -> None:
    """Start the API observation server."""
    import uvicorn
    from collectors.writer import EventWriter
    from honeypots.api.server import build_api_decoy

    out_path = Path(output_file) if output_file else None
    with EventWriter(out_path) as writer:
        app = build_api_decoy(writer.write)
        uvicorn.run(app, host=host, port=port)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2121, show_default=True)
@click.option("--banner", default="Microsoft FTP Service", show_default=True)
@click.option("--response-delay-ms", default=0, show_default=True, type=int)
@click.option("--output-file", default=None, help="JSONL output file path")
def run_ftp(
    host: str,
    port: int,
    banner: str,
    response_delay_ms: int,
    output_file: str | None,
) -> None:
    """Start the FTP observation server."""
    from collectors.writer import EventWriter
    from honeypots.ftp.server import start_ftp_observation_server

    out_path = Path(output_file) if output_file else None
    with EventWriter(out_path) as writer:
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
@click.option("--port", default=3389, show_default=True)
@click.option("--read-timeout-s", default=2.0, show_default=True, type=float)
@click.option("--response-delay-ms", default=0, show_default=True, type=int)
@click.option("--output-file", default=None, help="JSONL output file path")
def run_rdp(
    host: str,
    port: int,
    read_timeout_s: float,
    response_delay_ms: int,
    output_file: str | None,
) -> None:
    """Start the RDP banner observation server."""
    from collectors.writer import EventWriter
    from honeypots.rdp.server import start_rdp_banner_observer

    out_path = Path(output_file) if output_file else None
    with EventWriter(out_path) as writer:
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
