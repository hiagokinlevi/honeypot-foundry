"""Tests for SIEM format adapters."""
import json
from datetime import datetime, timezone

import pytest

from collectors.transports import CEFSyslogTransport, ElasticBulkTransport, SplunkHECTransport
from collectors.siem_adapter import to_splunk_hec, to_elastic_bulk, to_cef
from collectors.writer import EventWriter
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


def test_cef_escapes_attacker_controlled_extension_values():
    event = _make_event(
        username="root role=admin",
        path="/login\nsrc=10.0.0.9",
        method="POST",
        user_agent="scanner\\probe\r\ncs1Label=Injected",
    )

    cef = to_cef(event, device_vendor="k1N|Lab", device_product="Honeypot|Foundry")

    assert cef.startswith("CEF:0|k1N\\|Lab|Honeypot\\|Foundry|")
    assert "duser=root role\\=admin" in cef
    assert "request=/login\\nsrc\\=10.0.0.9" in cef
    assert "cs1=scanner\\\\probe\\r\\ncs1Label\\=Injected" in cef
    assert "\n" not in cef
    assert "\r" not in cef


def test_splunk_transport_posts_json(monkeypatch):
    event = _make_event(username="admin")
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["authorization"] = req.headers["Authorization"]
        captured["content_type"] = req.headers["Content-type"]
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Response()

    monkeypatch.setattr("collectors.transports.request.urlopen", fake_urlopen)

    transport = SplunkHECTransport(
        endpoint_url="https://splunk.example.com/services/collector/event",
        token="secret-token",
        index="security",
        source="sensor-a",
    )
    transport.send(event)

    assert captured["url"].endswith("/services/collector/event")
    assert captured["timeout"] == 5.0
    assert captured["authorization"] == "Splunk secret-token"
    assert captured["content_type"] == "application/json"
    assert captured["body"]["index"] == "security"
    assert captured["body"]["source"] == "sensor-a"


def test_splunk_transport_rejects_non_http_endpoint():
    with pytest.raises(ValueError, match="http or https"):
        SplunkHECTransport(endpoint_url="file:///tmp/hec", token="secret-token")


def test_elastic_transport_posts_ndjson_with_basic_auth(monkeypatch):
    event = _make_event()
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["authorization"] = req.headers["Authorization"]
        captured["content_type"] = req.headers["Content-type"]
        captured["body"] = req.data.decode("utf-8")
        return _Response()

    monkeypatch.setattr("collectors.transports.request.urlopen", fake_urlopen)

    transport = ElasticBulkTransport(
        endpoint_url="https://elastic.example.com/_bulk",
        index="security-events",
        username="elastic",
        password="changeme",
    )
    transport.send(event)

    assert captured["url"].endswith("/_bulk")
    assert captured["timeout"] == 5.0
    assert captured["authorization"].startswith("Basic ")
    assert captured["content_type"] == "application/x-ndjson"
    assert '"_index": "security-events"' in captured["body"]
    assert '"source_ip": "1.2.3.4"' in captured["body"]


def test_elastic_transport_requires_hostname():
    with pytest.raises(ValueError, match="hostname"):
        ElasticBulkTransport(endpoint_url="https:///bulk")


def test_cef_syslog_transport_builds_tcp_message(monkeypatch):
    event = _make_event(username="root")
    captured = {}

    class _Socket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def sendall(self, data):
            captured["data"] = data.decode("utf-8")

    def fake_create_connection(address, timeout):
        captured["address"] = address
        captured["timeout"] = timeout
        return _Socket()

    monkeypatch.setattr("collectors.transports.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("collectors.transports.socket.gethostname", lambda: "sensor-node")

    transport = CEFSyslogTransport(host="syslog.example.com", port=6514, protocol="tcp")
    transport.send(event)

    assert captured["address"] == ("syslog.example.com", 6514)
    assert captured["timeout"] == 5.0
    assert "sensor-node honeypot-foundry: CEF:0|" in captured["data"]
    assert "duser=root" in captured["data"]


def test_cef_syslog_transport_rejects_unknown_protocol():
    with pytest.raises(ValueError, match="tcp or udp"):
        CEFSyslogTransport(host="syslog.example.com", protocol="tls")


def test_cef_syslog_transport_rejects_whitespace_host():
    with pytest.raises(ValueError, match="must not contain whitespace"):
        CEFSyslogTransport(host="syslog relay")


def test_cef_syslog_transport_rejects_whitespace_app_name():
    with pytest.raises(ValueError, match="app name must not contain whitespace"):
        CEFSyslogTransport(host="syslog.example.com", app_name="honeypot foundry")


def test_cef_syslog_transport_rejects_invalid_facility():
    with pytest.raises(ValueError, match="facility must be between 0 and 23"):
        CEFSyslogTransport(host="syslog.example.com", facility=24)


def test_event_writer_preserves_output_when_transport_fails(capsys):
    event = _make_event()

    class BrokenTransport:
        def send(self, _event):
            raise RuntimeError("offline")

        def close(self):
            return None

    with EventWriter(transports=[BrokenTransport()]) as writer:
        writer.write(event)

    captured = capsys.readouterr()
    assert '"source_ip": "1.2.3.4"' in captured.out
    assert "transport error" in captured.err
