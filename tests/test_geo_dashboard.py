"""
Tests for analysis/geo_enrichment.py and reports/dashboard_metrics.py

Validates:
  - enrich_ip() returns GeoInfo for known stub IPs (8.8.8.8, 1.1.1.1)
  - enrich_ip() returns private indicator for RFC 1918 IPs
  - enrich_ip() returns unknown for unrecognised public IPs
  - enrich_event() populates event.metadata["geo"]
  - enrich_batch() deduplicates IP lookups
  - GeoInfo.to_dict() is JSON-serialisable
  - generate_dashboard_metrics() returns expected structure
  - Window filtering: LAST_HOUR excludes old events
  - top_source_ips is sorted descending by count
  - events_by_service counts correctly
  - unique_source_ips counts distinct IPs
  - credential_reuse counts credentials seen from ≥2 IPs
  - hourly_distribution is sorted by hour key
  - geo_distribution uses metadata if present
  - export_dashboard_metrics_json() returns valid JSON string
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.geo_enrichment import GeoInfo, enrich_batch, enrich_event, enrich_ip
from honeypots.common.event import HoneypotEvent, ServiceType
from reports.dashboard_metrics import (
    TimeWindow,
    export_dashboard_metrics_json,
    generate_dashboard_metrics,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    source_ip: str = "8.8.8.8",
    service: ServiceType = ServiceType.SSH,
    credential: str = "password",
    username: str = "root",
    user_agent: str | None = None,
    ts: datetime | None = None,
) -> HoneypotEvent:
    return HoneypotEvent(
        timestamp=ts or _now(),
        service=service,
        source_ip=source_ip,
        source_port=22,
        username=username,
        credential_observed=credential,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# geo_enrichment: enrich_ip
# ---------------------------------------------------------------------------

class TestEnrichIp:

    def test_returns_geo_info(self):
        result = enrich_ip("8.8.8.8")
        assert isinstance(result, GeoInfo)

    def test_known_google_dns_country(self):
        result = enrich_ip("8.8.8.8")
        assert result.country_code == "US"

    def test_known_cloudflare_country(self):
        result = enrich_ip("1.1.1.1")
        assert result.country_code == "AU"

    def test_known_cloudflare_org(self):
        result = enrich_ip("1.1.1.1")
        assert "Cloudflare" in result.org

    def test_private_ip_detected(self):
        result = enrich_ip("10.0.0.5")
        assert result.is_private is True

    def test_private_ip_country_code(self):
        result = enrich_ip("192.168.1.1")
        assert result.country_code == "--"

    def test_loopback_is_private(self):
        result = enrich_ip("127.0.0.1")
        assert result.is_private is True

    def test_unknown_public_ip_returns_geo_info(self):
        result = enrich_ip("203.0.113.5")   # TEST-NET-3, unrecognised in stub
        assert isinstance(result, GeoInfo)
        assert result.country_code == "??"

    def test_source_field_is_stub(self):
        result = enrich_ip("8.8.8.8")
        assert result.source == "stub"

    def test_ip_field_populated(self):
        result = enrich_ip("8.8.4.4")
        assert result.ip == "8.8.4.4"

    def test_google_asn(self):
        result = enrich_ip("8.8.8.8")
        assert result.asn == 15169


# ---------------------------------------------------------------------------
# geo_enrichment: enrich_event
# ---------------------------------------------------------------------------

class TestEnrichEvent:

    def test_adds_geo_to_metadata(self):
        event = _event(source_ip="8.8.8.8")
        enrich_event(event)
        assert "geo" in event.metadata

    def test_geo_is_dict(self):
        event = _event(source_ip="8.8.8.8")
        enrich_event(event)
        assert isinstance(event.metadata["geo"], dict)

    def test_geo_dict_has_country_code(self):
        event = _event(source_ip="8.8.8.8")
        enrich_event(event)
        assert "country_code" in event.metadata["geo"]

    def test_returns_event(self):
        event = _event(source_ip="1.1.1.1")
        returned = enrich_event(event)
        assert returned is event


# ---------------------------------------------------------------------------
# geo_enrichment: enrich_batch
# ---------------------------------------------------------------------------

class TestEnrichBatch:

    def test_all_events_get_geo(self):
        events = [_event(source_ip="8.8.8.8"), _event(source_ip="1.1.1.1")]
        enrich_batch(events)
        for e in events:
            assert "geo" in e.metadata

    def test_deduplicates_lookups(self):
        """Same IP enriched multiple times should reuse cached result."""
        events = [_event(source_ip="8.8.8.8") for _ in range(5)]
        # All events should get identical geo metadata
        enrich_batch(events)
        geo_values = [json.dumps(e.metadata["geo"], sort_keys=True) for e in events]
        assert len(set(geo_values)) == 1   # All the same

    def test_returns_same_list(self):
        events = [_event()]
        returned = enrich_batch(events)
        assert returned is events


# ---------------------------------------------------------------------------
# GeoInfo.to_dict
# ---------------------------------------------------------------------------

class TestGeoInfoToDict:

    def test_returns_dict(self):
        geo = enrich_ip("8.8.8.8")
        assert isinstance(geo.to_dict(), dict)

    def test_json_serialisable(self):
        geo = enrich_ip("10.0.0.1")
        json.dumps(geo.to_dict())   # Should not raise


# ---------------------------------------------------------------------------
# dashboard_metrics: generate_dashboard_metrics
# ---------------------------------------------------------------------------

class TestGenerateDashboardMetrics:

    def _events(self) -> list[HoneypotEvent]:
        t0 = _now()
        return [
            _event(source_ip="1.2.3.4", service=ServiceType.SSH,  credential="pass1", username="root",  ts=t0),
            _event(source_ip="5.6.7.8", service=ServiceType.SSH,  credential="pass1", username="admin", ts=t0),
            _event(source_ip="1.2.3.4", service=ServiceType.HTTP, credential="pass2", username="root",  ts=t0),
            _event(source_ip="9.9.9.9", service=ServiceType.API,  credential="pass3", username="test",  ts=t0),
        ]

    def test_returns_dict(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert isinstance(result, dict)

    def test_has_summary_key(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert "summary" in result

    def test_summary_total_events(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert result["summary"]["total_events"] == 4

    def test_summary_unique_ips(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert result["summary"]["unique_source_ips"] == 3

    def test_summary_events_by_service(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert result["summary"]["events_by_service"]["ssh"] == 2
        assert result["summary"]["events_by_service"]["http"] == 1
        assert result["summary"]["events_by_service"]["api"] == 1

    def test_credential_reuse_detected(self):
        # pass1 used from 1.2.3.4 AND 5.6.7.8 — should be counted as reuse
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert result["summary"]["credential_reuse"] >= 1

    def test_top_source_ips_sorted(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        counts = [entry["count"] for entry in result["top_source_ips"]]
        assert counts == sorted(counts, reverse=True)

    def test_top_usernames_present(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert "top_usernames" in result
        assert len(result["top_usernames"]) > 0

    def test_hourly_distribution_present(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert "hourly_distribution" in result

    def test_hourly_distribution_sorted(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        keys = list(result["hourly_distribution"].keys())
        assert keys == sorted(keys)

    def test_geo_distribution_present(self):
        result = generate_dashboard_metrics(self._events(), now=_now())
        assert "geo_distribution" in result

    def test_geo_distribution_uses_metadata(self):
        events = self._events()
        for e in events:
            e.metadata["geo"] = {"country_code": "CN", "country_name": "China"}
        result = generate_dashboard_metrics(events, now=_now())
        countries = [entry["country_code"] for entry in result["geo_distribution"]]
        assert "CN" in countries

    def test_window_all_time_includes_old_events(self):
        old_event = _event(ts=_now() - timedelta(days=30))
        result = generate_dashboard_metrics(
            [old_event], window=TimeWindow.ALL_TIME, now=_now()
        )
        assert result["summary"]["total_events"] == 1

    def test_window_last_hour_excludes_old_events(self):
        old_event = _event(ts=_now() - timedelta(hours=2))
        result = generate_dashboard_metrics(
            [old_event], window=TimeWindow.LAST_HOUR, now=_now()
        )
        assert result["summary"]["total_events"] == 0

    def test_window_last_24h_includes_recent(self):
        recent = _event(ts=_now() - timedelta(hours=12))
        result = generate_dashboard_metrics(
            [recent], window=TimeWindow.LAST_24H, now=_now()
        )
        assert result["summary"]["total_events"] == 1

    def test_empty_events_returns_zero_totals(self):
        result = generate_dashboard_metrics([], now=_now())
        assert result["summary"]["total_events"] == 0
        assert result["summary"]["unique_source_ips"] == 0

    def test_generated_at_field_present(self):
        result = generate_dashboard_metrics([], now=_now())
        assert "generated_at" in result
        assert result["generated_at"].endswith("Z")

    def test_window_field_set(self):
        result = generate_dashboard_metrics([], window=TimeWindow.LAST_7D, now=_now())
        assert result["window"] == "last_7d"


# ---------------------------------------------------------------------------
# export_dashboard_metrics_json
# ---------------------------------------------------------------------------

class TestExportJson:

    def test_returns_valid_json_string(self):
        events = [_event()]
        json_str = export_dashboard_metrics_json(events, now=_now())
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_has_summary(self):
        json_str = export_dashboard_metrics_json([_event()], now=_now())
        parsed = json.loads(json_str)
        assert "summary" in parsed

    def test_empty_events_produces_valid_json(self):
        json_str = export_dashboard_metrics_json([], now=_now())
        json.loads(json_str)   # Should not raise
