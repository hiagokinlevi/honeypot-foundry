import pytest

from honeypot_foundry_cli import build_parser


def test_siem_forward_batch_size_parses_valid_value():
    parser = build_parser()
    args = parser.parse_args([
        "run-http",
        "--port",
        "8080",
        "--siem-forward-batch-size",
        "25",
    ])

    assert args.siem_forward_batch_size == 25


def test_siem_forward_batch_size_rejects_zero():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            "run-http",
            "--port",
            "8080",
            "--siem-forward-batch-size",
            "0",
        ])
