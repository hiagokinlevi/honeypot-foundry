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
        f"src={event.source_ip}",
        f"spt={event.source_port}",
        f"rt={int(event.timestamp.timestamp() * 1000)}",
    ]
    if event.username:
        ext_parts.append(f"duser={event.username}")
    if event.path:
        ext_parts.append(f"request={event.path}")
    if event.method:
        ext_parts.append(f"requestMethod={event.method}")
    if event.user_agent:
        # CEF extensions use cs1 for custom string fields
        ext_parts.append(f"cs1={event.user_agent}")
        ext_parts.append("cs1Label=UserAgent")

    extension = " ".join(ext_parts)
    return f"CEF:0|{device_vendor}|{device_product}|1.0|{sig_id}|{name}|{severity}|{extension}"
