"""
Dashboard-Ready JSON Metric Export
=====================================
Computes aggregated statistics from a collection of honeypot events and returns
a structured JSON-serialisable dict suitable for ingestion by Grafana, Kibana,
Splunk dashboards, or any custom monitoring frontend.

Metrics computed:
  - Event totals and per-service breakdown
  - Unique source IP count + top attacker IPs
  - Hourly event distribution (for time-series charts)
  - Top observed usernames
  - Credential hash reuse count (same credential across ≥2 source IPs)
  - Top user-agents observed
  - Geo distribution (country counts, if geo metadata is present)
  - Attack pattern summary (spray, stuffing, burst — if metadata is present)

Usage:
    from reports.dashboard_metrics import generate_dashboard_metrics, TimeWindow

    metrics = generate_dashboard_metrics(events, window=TimeWindow.LAST_24H)
    print(metrics["summary"]["total_events"])
    print(metrics["top_source_ips"])
    # Pass to json.dumps() for export
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from honeypots.common.event import HoneypotEvent


# ---------------------------------------------------------------------------
# Time window
# ---------------------------------------------------------------------------

class TimeWindow(str, Enum):
    """Predefined time windows for metric aggregation."""
    LAST_HOUR  = "last_hour"
    LAST_24H   = "last_24h"
    LAST_7D    = "last_7d"
    ALL_TIME   = "all_time"


_WINDOW_DELTA: dict[TimeWindow, timedelta | None] = {
    TimeWindow.LAST_HOUR: timedelta(hours=1),
    TimeWindow.LAST_24H:  timedelta(hours=24),
    TimeWindow.LAST_7D:   timedelta(days=7),
    TimeWindow.ALL_TIME:  None,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _filter_by_window(
    events: list[HoneypotEvent],
    window: TimeWindow,
    now: datetime | None = None,
) -> list[HoneypotEvent]:
    """Return events within the given time window."""
    delta = _WINDOW_DELTA[window]
    if delta is None:
        return list(events)
    cutoff = (now or datetime.now(tz=timezone.utc)) - delta
    return [e for e in events if e.timestamp >= cutoff]


def _extract_credential_key(event: HoneypotEvent) -> str | None:
    """Extract the hash_prefix from a masked credential, or None."""
    if event.credential_observed and "hash_prefix=" in event.credential_observed:
        import re
        m = re.search(r"hash_prefix=([0-9a-f]+)", event.credential_observed)
        if m:
            return m.group(1)
    return None


def _hourly_buckets(events: list[HoneypotEvent]) -> dict[str, int]:
    """Return a dict of hour-string → event count for timeline charts."""
    counts: dict[str, int] = {}
    for event in events:
        # Round down to the hour
        hour_key = event.timestamp.strftime("%Y-%m-%dT%H:00:00Z")
        counts[hour_key] = counts.get(hour_key, 0) + 1
    # Return sorted by key
    return dict(sorted(counts.items()))


def _credential_reuse(events: list[HoneypotEvent]) -> int:
    """
    Count credentials (by hash prefix) observed from ≥2 distinct source IPs.
    This indicates credential stuffing — the same stolen credential tried
    from multiple attack nodes.
    """
    cred_ips: dict[str, set[str]] = defaultdict(set)
    for event in events:
        key = _extract_credential_key(event)
        if key:
            cred_ips[key].add(event.source_ip)
    return sum(1 for ips in cred_ips.values() if len(ips) >= 2)


def _geo_distribution(events: list[HoneypotEvent]) -> list[dict[str, Any]]:
    """
    Compute country distribution from geo metadata if available.

    Returns a list of {country_code, country_name, count} dicts sorted by
    count descending.
    """
    country_counter: Counter[tuple[str, str]] = Counter()
    for event in events:
        geo = event.metadata.get("geo")
        if geo and isinstance(geo, dict):
            code = geo.get("country_code", "??")
            name = geo.get("country_name", "Unknown")
            country_counter[(code, name)] += 1

    return [
        {"country_code": code, "country_name": name, "event_count": count}
        for (code, name), count in country_counter.most_common(20)
    ]


def _top_n(items: list, n: int) -> list[dict[str, Any]]:
    """
    Count items and return the top-N as [{"value": v, "count": c}, ...].
    """
    counter: Counter = Counter(items)
    return [{"value": v, "count": c} for v, c in counter.most_common(n)]


# ---------------------------------------------------------------------------
# Main export function
# ---------------------------------------------------------------------------

def generate_dashboard_metrics(
    events: list[HoneypotEvent],
    window: TimeWindow = TimeWindow.LAST_24H,
    top_n: int = 10,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Compute aggregated metrics from honeypot events for dashboard display.

    Args:
        events:  All HoneypotEvent objects to analyse.
        window:  Time window to filter events before computing metrics.
                 Use TimeWindow.ALL_TIME to include all events.
        top_n:   How many entries to include in top-N lists.
        now:     Override for current time (for testing). Defaults to UTC now.

    Returns:
        JSON-serialisable dict with the following top-level keys::

            {
                "generated_at":    "2026-04-06T10:00:00Z",
                "window":          "last_24h",
                "summary": {
                    "total_events":        N,
                    "unique_source_ips":   N,
                    "credential_reuse":    N,
                    "events_by_service":   {"ssh": N, "http": N, "api": N}
                },
                "top_source_ips":       [{"value": ip, "count": N}, ...],
                "top_usernames":        [{"value": u,  "count": N}, ...],
                "top_user_agents":      [{"value": ua, "count": N}, ...],
                "hourly_distribution":  {"2026-04-06T09:00:00Z": N, ...},
                "geo_distribution":     [{"country_code": "CN", "event_count": N}, ...],
            }
    """
    filtered = _filter_by_window(events, window, now=now)

    events_by_service: dict[str, int] = {}
    for event in filtered:
        key = event.service.value
        events_by_service[key] = events_by_service.get(key, 0) + 1

    unique_ips = len({e.source_ip for e in filtered})

    summary = {
        "total_events":      len(filtered),
        "unique_source_ips": unique_ips,
        "credential_reuse":  _credential_reuse(filtered),
        "events_by_service": events_by_service,
    }

    top_ips = _top_n([e.source_ip for e in filtered], top_n)
    top_usernames = _top_n(
        [e.username for e in filtered if e.username],
        top_n,
    )
    top_user_agents = _top_n(
        [e.user_agent for e in filtered if e.user_agent],
        top_n,
    )

    ts = (now or datetime.now(tz=timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "generated_at":       ts,
        "window":             window.value,
        "summary":            summary,
        "top_source_ips":     top_ips,
        "top_usernames":      top_usernames,
        "top_user_agents":    top_user_agents,
        "hourly_distribution": _hourly_buckets(filtered),
        "geo_distribution":   _geo_distribution(filtered),
    }


def export_dashboard_metrics_json(
    events: list[HoneypotEvent],
    window: TimeWindow = TimeWindow.LAST_24H,
    top_n: int = 10,
    indent: int = 2,
    now: datetime | None = None,
) -> str:
    """
    Generate dashboard metrics and return them as a formatted JSON string.

    Args:
        events:  HoneypotEvent list.
        window:  Time window filter.
        top_n:   Top-N list size.
        indent:  JSON indentation level.
        now:     Override for current time.

    Returns:
        JSON string suitable for writing to a file or HTTP response.
    """
    metrics = generate_dashboard_metrics(events, window=window, top_n=top_n, now=now)
    return json.dumps(metrics, indent=indent, ensure_ascii=False)
