import json

from fastapi.testclient import TestClient

from honeypots.http import create_http_app
from honeypots.api import create_api_app


def _assert_truncation_event(event: dict, original_body: bytes, cap: int) -> None:
    assert event["body_truncated"] is True
    assert event["original_body_bytes"] == len(original_body)
    assert event["captured_body_bytes"] == cap

    captured = event.get("body", "")
    if isinstance(captured, str):
        captured_bytes = captured.encode("utf-8", errors="ignore")
    else:
        captured_bytes = captured

    assert len(captured_bytes) <= cap


def test_http_and_api_request_body_truncation_semantics(tmp_path):
    cap = 16
    payload = b"A" * 64

    # HTTP
    http_events = []

    def collect_http(evt):
        http_events.append(evt)

    http_app = create_http_app(event_callback=collect_http, max_request_body_bytes=cap)
    http_client = TestClient(http_app)
    http_client.post("/anything", data=payload, headers={"content-type": "text/plain"})

    assert http_events, "expected HTTP honeypot to emit an event"
    _assert_truncation_event(http_events[-1], payload, cap)

    # API
    api_events = []

    def collect_api(evt):
        api_events.append(evt)

    api_app = create_api_app(event_callback=collect_api, max_request_body_bytes=cap)
    api_client = TestClient(api_app)
    api_client.post("/token", data=payload, headers={"content-type": "application/octet-stream"})

    assert api_events, "expected API honeypot to emit an event"
    _assert_truncation_event(api_events[-1], payload, cap)
