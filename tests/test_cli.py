from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_show_helm_reports_chart_path_and_overrides():
    result = CliRunner().invoke(cli, ["show-helm"])

    assert result.exit_code == 0
    assert "Helm chart:" in result.output
    assert str(Path("helm/honeypot-foundry").resolve()) in result.output
    assert "--set services.ftp.enabled=true" in result.output
    assert "--set podDisruptionBudget.enabled=true" in result.output

