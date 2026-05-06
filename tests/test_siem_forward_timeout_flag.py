from __future__ import annotations

from honeypot_foundry_cli import (
    _post_elastic_bulk,
    _post_splunk_event,
    build_forwarder_config,
    build_parser,
)


class _DummySession:
    def __init__(self) -> None:
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return {"ok": True}


def test_siem_forward_timeout_flag_default_and_override_propagates_and_enforces_timeout():
    parser = build_parser()

    default_args = parser.parse_args(["run-http"])
    default_cfg = build_forwarder_config(default_args)
    assert default_cfg["siem_forward_timeout_seconds"] == 5.0

    override_args = parser.parse_args([
        "--siem-forward-timeout-seconds",
        "9.5",
        "run-http",
    ])
    override_cfg = build_forwarder_config(override_args)
    assert override_cfg["siem_forward_timeout_seconds"] == 9.5

    session = _DummySession()

    _post_splunk_event(session, "https://splunk.example/hec", {"event": 1}, override_cfg["siem_forward_timeout_seconds"])
    _post_elastic_bulk(session, "https://elastic.example/_bulk", "{}\n", override_cfg["siem_forward_timeout_seconds"])

    assert session.calls[0][1]["timeout"] == 9.5
    assert session.calls[1][1]["timeout"] == 9.5
