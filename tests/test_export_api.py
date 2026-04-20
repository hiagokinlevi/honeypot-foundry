import json

from fastapi.testclient import TestClient

from collectors.export_api import create_export_api


def _write_events(path):
    events = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "service": "ssh",
            "source_ip": "1.1.1.1",
            "event_type": "login_attempt",
        },
        {
            "timestamp": "2026-01-01T01:00:00Z",
            "service": "http",
            "source_ip": "2.2.2.2",
            "event_type": "request",
        },
        {
            "timestamp": "2026-01-01T02:00:00Z",
            "service": "ssh",
            "source_ip": "1.1.1.1",
            "event_type": "login_attempt",
        },
    ]
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def test_export_events_filters(tmp_path):
    event_file = tmp_path / "events.jsonl"
    _write_events(event_file)
    client = TestClient(create_export_api(str(event_file)))

    resp = client.get("/export/events", params={"service": "ssh", "limit": 10})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert all(evt["service"] == "ssh" for evt in body["events"])


def test_export_stats(tmp_path):
    event_file = tmp_path / "events.jsonl"
    _write_events(event_file)
    client = TestClient(create_export_api(str(event_file)))

    resp = client.get("/export/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == 3
    assert body["events_by_service"]["ssh"] == 2
    assert body["events_by_service"]["http"] == 1
    assert body["top_source_ips"][0]["source_ip"] == "1.1.1.1"
    assert body["top_source_ips"][0]["count"] == 2
