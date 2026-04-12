"""
SIEM adapter for honeypot events.

Formats HoneypotEvents for ingestion by common SIEM platforms:
- Splunk HEC (HTTP Event Collector)
- Elastic/OpenSearch bulk ingest
- Generic CEF (Common Event Format) for syslog-based SIEMs

All adapters produce strings or dicts — actual transport (HTTP, syslog)
is handled by the caller to keep this module dependency-free.
"""
from __future__ import annotations
import json
from datetime import timezone
from honeypots.common.event import HoneypotEvent


def _escape_cef_header(value: str) -> str:
    """Escape CEF header delimiters in static formatter fields."""
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _escape_cef_extension(value: object) -> str:
    """Escape attacker-controlled CEF extension values for syslog delivery."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _contains_control_characters(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _validate_siem_routing_value(value: str, *, field_name: str) -> str:
    """Reject malformed SIEM routing values before building outbound payloads."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    if value != value.strip():
        raise ValueError(f"{field_name} must not start or end with whitespace.")
    if _contains_control_characters(value):
        raise ValueError(f"{field_name} must not contain control characters.")
    return value


def to_splunk_hec(event: HoneypotEvent, index: str = "honeypot", source: str = "honeypot-foundry") -> dict:
    """
    Format a HoneypotEvent for Splunk HEC (HTTP Event Collector).

    Returns a dict ready for JSON serialization and POST to
    https://<splunk>:8088/services/collector/event

    Args:
        event:  The HoneypotEvent to format.
        index:  Splunk index name.
        source: Splunk source field value.

    Returns:
        Dict conforming to Splunk HEC event format.
    """
    ts = event.timestamp.astimezone(timezone.utc).timestamp()
    index = _validate_siem_routing_value(index, field_name="Splunk index")
    source = _validate_siem_routing_value(source, field_name="Splunk source")
    return {
        "time": ts,
        "index": index,
        "source": source,
        "sourcetype": f"honeypot:{event.service.value}",
        "event": event.model_dump(mode="json"),
    }


def to_elastic_bulk(event: HoneypotEvent, index: str = "honeypot-events") -> str:
    """
    Format a HoneypotEvent as an Elastic bulk API line pair.

    Returns two newline-separated JSON strings:
      Line 1: action/metadata  {"index": {"_index": "..."}}
      Line 2: document body

    Concatenate multiple events and POST to /_bulk.

    Args:
        event: The HoneypotEvent to format.
        index: Elastic index name.

    Returns:
        Two-line NDJSON string (includes trailing newline).
    """
    index = _validate_siem_routing_value(index, field_name="Elastic index")
    action = json.dumps({"index": {"_index": index}})
    doc = json.dumps(event.model_dump(mode="json"))
    return f"{action}\n{doc}\n"


def to_cef(event: HoneypotEvent, device_vendor: str = "k1N", device_product: str = "HoneypotFoundry") -> str:
    """
    Format a HoneypotEvent as a CEF (Common Event Format) syslog string.

    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension

    Suitable for forwarding to any CEF-compatible SIEM (ArcSight, QRadar, Sentinel).

    Args:
        event:          The HoneypotEvent to format.
        device_vendor:  CEF Device Vendor field.
        device_product: CEF Device Product field.

    Returns:
        CEF-formatted string.
    """
    # Map service type to CEF signature IDs
    sig_map = {"ssh": "1001", "http": "1002", "api": "1003"}
    sig_id = sig_map.get(event.service.value, "1000")
    name = f"{event.service.value.upper()} connection attempt observed"

    # CEF severity: 0-10 (use 5 as default — observation, not confirmed attack)
    severity = 5

    ext_parts = [
        f"src={_escape_cef_extension(event.source_ip)}",
        f"spt={_escape_cef_extension(event.source_port)}",
        f"rt={_escape_cef_extension(int(event.timestamp.timestamp() * 1000))}",
    ]
    if event.username:
        ext_parts.append(f"duser={_escape_cef_extension(event.username)}")
    if event.path:
        ext_parts.append(f"request={_escape_cef_extension(event.path)}")
    if event.method:
        ext_parts.append(f"requestMethod={_escape_cef_extension(event.method)}")
    if event.user_agent:
        # CEF extensions use cs1 for custom string fields
        ext_parts.append(f"cs1={_escape_cef_extension(event.user_agent)}")
        ext_parts.append("cs1Label=UserAgent")

    extension = " ".join(ext_parts)
    return (
        f"CEF:0|{_escape_cef_header(device_vendor)}|"
        f"{_escape_cef_header(device_product)}|1.0|{sig_id}|"
        f"{_escape_cef_header(name)}|{severity}|{extension}"
    )
