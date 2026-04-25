from collectors.forwarder import SIEMForwarder


def test_queue_drop_emits_telemetry(monkeypatch):
    emitted = []

    f = SIEMForwarder(mode="splunk", splunk_url="http://x", splunk_token="t", max_queue=2, retry_interval=60, telemetry_emitter=emitted.append)

    def fail(_event):
        return False, "down"

    monkeypatch.setattr(f, "_deliver", fail)

    f.submit({"event_id": "e1"})
    f.submit({"event_id": "e2"})
    f.submit({"event_id": "e3"})

    assert f.queue_depth == 2
    types = [e["event_type"] for e in emitted]
    assert "siem_delivery_retry" in types
    assert "siem_delivery_dropped" in types

    f.close()


def test_retry_loop_emits_retry_event(monkeypatch):
    emitted = []
    f = SIEMForwarder(mode="splunk", splunk_url="http://x", splunk_token="t", max_queue=5, retry_interval=0.1, telemetry_emitter=emitted.append)

    calls = {"n": 0}

    def flap(_event):
        calls["n"] += 1
        if calls["n"] < 2:
            return False, "fail_once"
        return True, ""

    monkeypatch.setattr(f, "_deliver", flap)

    f.submit({"event_id": "e1"})

    import time

    time.sleep(0.25)
    assert any(e["event_type"] == "siem_delivery_retry" for e in emitted)
    f.close()
