from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict


_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _is_uuid4(value: str) -> bool:
    return bool(_UUID_V4_RE.match(value))


def ensure_event_id(event: Dict[str, Any]) -> Dict[str, Any]:
    existing = event.get("event_id")
    if not isinstance(existing, str) or not _is_uuid4(existing):
        event["event_id"] = str(uuid.uuid4())
    return event


def load_schema(schema_path: str | Path) -> Dict[str, Any]:
    with open(schema_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_and_normalize_event(event: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal, fast-path normalization currently used prior to JSONL/SIEM forwarding.
    # Keep this bounded and avoid heavy dependencies for runtime emitters.
    normalized = dict(event)
    ensure_event_id(normalized)

    # Backward-compatible lightweight schema guardrails.
    required = schema.get("required", [])
    for key in required:
        if key not in normalized:
            raise ValueError(f"Missing required event field: {key}")

    return normalized
