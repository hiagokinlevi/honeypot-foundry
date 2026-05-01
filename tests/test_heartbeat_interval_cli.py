import pytest

from honeypot_foundry_cli import DEFAULT_HEARTBEAT_INTERVAL_SECONDS, build_parser


def test_heartbeat_interval_defaults_to_current_behavior() -> None:
    parser = build_parser()
    args = parser.parse_args(["run-http", "--port", "8080"])
    assert args.heartbeat_interval_seconds == DEFAULT_HEARTBEAT_INTERVAL_SECONDS


def test_heartbeat_interval_accepts_positive_value() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["run-ssh", "--port", "2222", "--heartbeat-interval-seconds", "15"]
    )
    assert args.heartbeat_interval_seconds == 15


@pytest.mark.parametrize("bad_value", ["0", "-1"])
def test_heartbeat_interval_rejects_non_positive_values(bad_value: str) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["run-api", "--port", "8000", "--heartbeat-interval-seconds", bad_value]
        )
