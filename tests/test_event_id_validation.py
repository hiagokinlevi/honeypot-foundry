import re

from collectors.event_schema import validate_and_normalize_event


UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def test_validate_and_normalize_event_adds_uuid4_event_id_when_missing():
    schema = {
        "type": "object",
        "required": ["timestamp", "event_type", "source_ip", "event_id"],
    }
    event = {
        "timestamp": "2026-04-22T00:00:00Z",
        "event_type": "ssh_auth_attempt",
        "source_ip": "203.0.113.10",
    }

    normalized = validate_and_normalize_event(event, schema)

    assert "event_id" in normalized
    assert isinstance(normalized["event_id"], str)
    assert UUID_V4_RE.match(normalized["event_id"])
