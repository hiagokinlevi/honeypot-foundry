"""Tests for SIEM format adapters."""
import json
from datetime import datetime, timezone
from collectors.siem_adapter import to_splunk_hec, to_elastic_bulk, to_cef
from honeypots.common.event import HoneypotEvent, ServiceType


def _make_event(**kwargs) -> HoneypotEvent:
    return HoneypotEvent(
        service=ServiceType.SSH,
        source_ip="1.2.3.4",
        source_port=1234,
        timestamp=datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc),
        **kwargs,
    )


def test_splunk_hec_format():
    event = _make_event(username="admin")
    hec = to_splunk_hec(event)
    assert "time" in hec
    assert hec["sourcetype"] == "honeypot:ssh"
    assert hec["event"]["source_ip"] == "1.2.3.4"


def test_elastic_bulk_two_lines():
    event = _make_event()
    result = to_elastic_bulk(event)
    lines = result.strip().split("\n")
    assert len(lines) == 2
    action = json.loads(lines[0])
    assert "index" in action
    doc = json.loads(lines[1])
    assert doc["source_ip"] == "1.2.3.4"


def test_cef_format_contains_src():
    event = _make_event(username="root", path="/login")
    cef = to_cef(event)
    assert cef.startswith("CEF:0|")
    assert "src=1.2.3.4" in cef
    assert "duser=root" in cef


def test_cef_no_username():
    event = _make_event()
    cef = to_cef(event)
    assert "duser=" not in cef
