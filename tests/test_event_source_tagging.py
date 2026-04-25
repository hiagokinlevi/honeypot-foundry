import importlib
import json
import pkgutil
from typing import Any, Callable

import pytest


def _find_attr(attr_name: str) -> Any:
    """Best-effort lookup for shared builders/emitters without hard-coding internals."""
    candidate_roots = ["collectors", "honeypots", "cli"]
    for root in candidate_roots:
        try:
            pkg = importlib.import_module(root)
        except Exception:
            continue

        modules = [pkg.__name__]
        if hasattr(pkg, "__path__"):
            for m in pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg.__name__}."):
                modules.append(m.name)

        for mod_name in modules:
            try:
                mod = importlib.import_module(mod_name)
            except Exception:
                continue
            if hasattr(mod, attr_name):
                return getattr(mod, attr_name)

    raise AssertionError(f"Could not locate attribute '{attr_name}' in project modules")


@pytest.mark.parametrize("value", ["edge-dmz-1", "k8s-node-a", "sensor-01"])
def test_event_source_is_injected_into_built_event(value: str) -> None:
    """
    Verifies shared/default event builder carries static event_source tag.
    This intentionally discovers the builder dynamically to stay resilient to module layout.
    """
    build_event = _find_attr("build_event")

    # Build minimal event payload expected by existing schema/defaults.
    event = build_event(
        honeypot_type="http",
        src_ip="203.0.113.10",
        action="request",
        outcome="denied",
        event_source=value,
    )

    assert isinstance(event, dict)
    assert event.get("event_source") == value


def test_event_source_non_empty_validation() -> None:
    """Empty/whitespace event_source must be rejected."""
    validator = None
    for name in ("validate_non_empty_string", "validate_event_source", "_validate_event_source"):
        try:
            validator = _find_attr(name)
            break
        except AssertionError:
            continue

    if validator is None:
        # If project validates via builder only, assert builder rejects bad values.
        build_event = _find_attr("build_event")
        with pytest.raises((ValueError, AssertionError)):
            build_event(
                honeypot_type="http",
                src_ip="203.0.113.11",
                action="request",
                outcome="denied",
                event_source="   ",
            )
        return

    with pytest.raises((ValueError, AssertionError)):
        validator("   ")


def test_event_source_survives_jsonl_serialization() -> None:
    """Ensures emitted JSONL line preserves event_source field."""
    build_event = _find_attr("build_event")
    event = build_event(
        honeypot_type="ssh",
        src_ip="198.51.100.7",
        action="auth_attempt",
        outcome="denied",
        event_source="edge-dmz-1",
    )

    line = json.dumps(event)
    parsed = json.loads(line)
    assert parsed["event_source"] == "edge-dmz-1"
