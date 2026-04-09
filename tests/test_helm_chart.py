from pathlib import Path
import subprocess


CHART_DIR = Path(__file__).resolve().parents[1] / "helm" / "honeypot-foundry"


def render_chart(*args: str) -> str:
    completed = subprocess.run(
        ["helm", "template", "honeypot-foundry", str(CHART_DIR), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def test_helm_chart_renders_network_policies_by_default():
    rendered = render_chart()

    assert rendered.count("kind: NetworkPolicy") == 3
    assert "name: honeypot-foundry-ssh" in rendered
    assert "name: honeypot-foundry-http" in rendered
    assert "name: honeypot-foundry-api" in rendered
    assert "egress: []" in rendered


def test_helm_chart_can_disable_network_policies():
    rendered = render_chart("--set", "networkPolicy.enabled=false")

    assert "kind: NetworkPolicy" not in rendered
