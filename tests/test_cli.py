from pathlib import Path

import pytest
from click.testing import CliRunner

from cli.main import build_transports, cli
from collectors.transports import CEFSyslogTransport, ElasticBulkTransport, SplunkHECTransport


def test_show_helm_reports_chart_path_and_overrides():
    result = CliRunner().invoke(cli, ["show-helm"])

    assert result.exit_code == 0
    assert "Helm chart:" in result.output
    assert str(Path("helm/honeypot-foundry").resolve()) in result.output
    assert "--set services.ftp.enabled=true" in result.output
    assert "--set podDisruptionBudget.enabled=true" in result.output


def test_build_transports_requires_splunk_token_with_url():
    with pytest.raises(Exception) as exc_info:
        build_transports(
            splunk_hec_url="https://splunk.example.com/services/collector/event",
            splunk_hec_token=None,
            splunk_index="honeypot",
            splunk_source="honeypot-foundry",
            elastic_url=None,
            elastic_index="honeypot-events",
            elastic_username=None,
            elastic_password=None,
            cef_syslog_host=None,
            cef_syslog_port=514,
            cef_syslog_protocol="udp",
        )

    assert "--splunk-hec-token is required" in str(exc_info.value)


def test_build_transports_returns_requested_backends():
    transports = build_transports(
        splunk_hec_url="https://splunk.example.com/services/collector/event",
        splunk_hec_token="token",
        splunk_index="security",
        splunk_source="sensor-a",
        elastic_url="https://elastic.example.com/_bulk",
        elastic_index="honeypot-events",
        elastic_username="elastic",
        elastic_password="changeme",
        cef_syslog_host="sentinel-gateway",
        cef_syslog_port=6514,
        cef_syslog_protocol="tcp",
    )

    assert len(transports) == 3
    assert isinstance(transports[0], SplunkHECTransport)
    assert isinstance(transports[1], ElasticBulkTransport)
    assert isinstance(transports[2], CEFSyslogTransport)


def test_run_http_help_shows_siem_options():
    result = CliRunner().invoke(cli, ["run-http", "--help"])

    assert result.exit_code == 0
    assert "--splunk-hec-url" in result.output
    assert "--elastic-url" in result.output
    assert "--cef-syslog-host" in result.output
