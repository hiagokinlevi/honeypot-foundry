"""
Tests for analysis/threat_intel.py — ThreatIntelEnricher and feed parsers.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.threat_intel import (
    FeedConfig,
    ThreatIntelEnricher,
    ThreatIntelMatch,
    parse_abuseipdb_json,
    parse_csv_feed,
    parse_ip_list,
    parse_stix2_json,
)


# ===========================================================================
# ThreatIntelMatch
# ===========================================================================

class TestThreatIntelMatch:
    def test_high_confidence_true(self):
        m = ThreatIntelMatch(ip="1.2.3.4", source="test", confidence=80)
        assert m.is_high_confidence

    def test_high_confidence_false(self):
        m = ThreatIntelMatch(ip="1.2.3.4", source="test", confidence=50)
        assert not m.is_high_confidence

    def test_to_dict_has_required_keys(self):
        m = ThreatIntelMatch(ip="1.2.3.4", source="test")
        d = m.to_dict()
        for key in ("ip", "source", "categories", "confidence", "tags"):
            assert key in d


# ===========================================================================
# parse_ip_list
# ===========================================================================

class TestParseIpList:
    _cfg = FeedConfig(name="test", default_confidence=60, default_categories=["scanner"])

    def test_parses_single_ip(self):
        matches = parse_ip_list("185.220.101.1\n", self._cfg)
        assert len(matches) == 1
        assert matches[0].ip == "185.220.101.1"

    def test_parses_cidr(self):
        matches = parse_ip_list("10.0.0.0/8\n", self._cfg)
        assert len(matches) == 1
        assert matches[0].matched_cidr == "10.0.0.0/8"

    def test_skips_comments(self):
        text = "# This is a comment\n1.2.3.4\n"
        matches = parse_ip_list(text, self._cfg)
        assert len(matches) == 1

    def test_skips_empty_lines(self):
        text = "\n\n1.2.3.4\n\n"
        matches = parse_ip_list(text, self._cfg)
        assert len(matches) == 1

    def test_inline_comment_captured_as_tag(self):
        text = "1.2.3.4 # tor-exit node\n"
        matches = parse_ip_list(text, self._cfg)
        assert matches[0].tags.get("comment") == "tor-exit node"

    def test_default_categories_applied(self):
        matches = parse_ip_list("1.2.3.4\n", self._cfg)
        assert "scanner" in matches[0].categories

    def test_default_confidence_applied(self):
        matches = parse_ip_list("1.2.3.4\n", self._cfg)
        assert matches[0].confidence == 60

    def test_invalid_ip_skipped(self):
        matches = parse_ip_list("not-an-ip\n1.2.3.4\n", self._cfg)
        assert len(matches) == 1

    def test_ipv6_parsed(self):
        matches = parse_ip_list("2001:db8::1\n", self._cfg)
        assert len(matches) == 1


# ===========================================================================
# parse_csv_feed
# ===========================================================================

class TestParseCsvFeed:
    _cfg = FeedConfig(name="csv-test", default_confidence=50)

    def test_parses_ip_and_category(self):
        csv = "ip,category,confidence\n1.2.3.4,scanner,90\n"
        matches = parse_csv_feed(csv, self._cfg)
        assert len(matches) == 1
        assert matches[0].ip == "1.2.3.4"
        assert "scanner" in matches[0].categories
        assert matches[0].confidence == 90

    def test_skips_invalid_ip(self):
        csv = "ip,category\nnot-an-ip,scanner\n1.2.3.4,botnet\n"
        matches = parse_csv_feed(csv, self._cfg)
        assert len(matches) == 1

    def test_extra_columns_become_tags(self):
        csv = "ip,category,country\n1.2.3.4,scanner,CN\n"
        matches = parse_csv_feed(csv, self._cfg)
        assert matches[0].tags.get("country") == "CN"

    def test_confidence_clamped_to_100(self):
        csv = "ip,category,confidence\n1.2.3.4,x,150\n"
        matches = parse_csv_feed(csv, self._cfg)
        assert matches[0].confidence == 100


# ===========================================================================
# parse_abuseipdb_json
# ===========================================================================

class TestParseAbuseIpDbJson:
    _cfg = FeedConfig(name="abuseipdb", default_confidence=50, default_categories=["abuse"])

    _SAMPLE = json.dumps({
        "data": [
            {
                "ipAddress": "192.168.1.1",
                "abuseConfidenceScore": 95,
                "countryCode": "RU",
                "lastReportedAt": "2026-04-01T00:00:00+00:00",
                "totalReports": 42,
            }
        ]
    })

    def test_parses_ip(self):
        matches = parse_abuseipdb_json(self._SAMPLE, self._cfg)
        assert len(matches) == 1
        assert matches[0].ip == "192.168.1.1"

    def test_parses_confidence(self):
        matches = parse_abuseipdb_json(self._SAMPLE, self._cfg)
        assert matches[0].confidence == 95

    def test_parses_country_tag(self):
        matches = parse_abuseipdb_json(self._SAMPLE, self._cfg)
        assert matches[0].tags.get("country") == "RU"

    def test_parses_last_seen(self):
        matches = parse_abuseipdb_json(self._SAMPLE, self._cfg)
        assert "2026" in matches[0].last_seen

    def test_empty_data_returns_empty(self):
        empty = json.dumps({"data": []})
        matches = parse_abuseipdb_json(empty, self._cfg)
        assert matches == []

    def test_invalid_json_returns_empty(self):
        matches = parse_abuseipdb_json("not-json", self._cfg)
        assert matches == []


# ===========================================================================
# parse_stix2_json
# ===========================================================================

class TestParseStix2Json:
    _cfg = FeedConfig(name="stix2", default_confidence=60, default_categories=["malware"])

    _SAMPLE = json.dumps({
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--abc123",
                "name": "Log4Shell scanner",
                "pattern": "[ipv4-addr:value = '185.220.101.1']",
                "labels": ["scanner", "exploit"],
                "modified": "2026-04-01T00:00:00Z",
            },
            {
                "type": "indicator",
                "id": "indicator--def456",
                "name": "CIDR block",
                "pattern": "[ipv4-addr:value = '10.0.0.0/8']",
                "labels": ["internal"],
            },
            {
                "type": "malware",     # should be skipped
                "id": "malware--xyz",
            }
        ]
    })

    def test_parses_ipv4_indicator(self):
        matches = parse_stix2_json(self._SAMPLE, self._cfg)
        ips = [m.ip for m in matches]
        assert "185.220.101.1" in ips

    def test_parses_cidr_indicator(self):
        matches = parse_stix2_json(self._SAMPLE, self._cfg)
        ips = [m.ip for m in matches]
        assert "10.0.0.0/8" in ips

    def test_skips_non_indicator_objects(self):
        matches = parse_stix2_json(self._SAMPLE, self._cfg)
        assert len(matches) == 2

    def test_labels_become_categories(self):
        matches = parse_stix2_json(self._SAMPLE, self._cfg)
        m = next(m for m in matches if m.ip == "185.220.101.1")
        assert "scanner" in m.categories

    def test_stix_id_in_tags(self):
        matches = parse_stix2_json(self._SAMPLE, self._cfg)
        m = next(m for m in matches if m.ip == "185.220.101.1")
        assert "stix_id" in m.tags

    def test_invalid_json_returns_empty(self):
        matches = parse_stix2_json("not-json", self._cfg)
        assert matches == []


# ===========================================================================
# ThreatIntelEnricher
# ===========================================================================

class TestThreatIntelEnricher:
    def test_load_ip_list_returns_count(self):
        enricher = ThreatIntelEnricher()
        count = enricher.load_feed_text("1.2.3.4\n5.6.7.8\n", source="test")
        assert count == 2

    def test_lookup_exact_match(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="blocklist")
        match = enricher.lookup("1.2.3.4")
        assert match is not None
        assert match.source == "blocklist"

    def test_lookup_no_match_returns_none(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="blocklist")
        assert enricher.lookup("9.9.9.9") is None

    def test_lookup_cidr_match(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("10.0.0.0/8\n", source="internal")
        match = enricher.lookup("10.50.100.200")
        assert match is not None
        assert match.matched_cidr == "10.0.0.0/8"

    def test_lookup_cidr_no_match_outside_range(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("10.0.0.0/24\n", source="test")
        assert enricher.lookup("10.0.1.1") is None

    def test_lookup_invalid_ip_returns_none(self):
        enricher = ThreatIntelEnricher()
        assert enricher.lookup("not-an-ip") is None

    def test_entry_count(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n5.6.7.8\n10.0.0.0/8\n", source="test")
        assert enricher.entry_count == 3

    def test_stats_dict(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n10.0.0.0/8\n", source="test")
        stats = enricher.stats()
        assert stats["exact_entries"] == 1
        assert stats["cidr_entries"] == 1
        assert stats["total_entries"] == 2

    def test_clear_removes_all(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="test")
        enricher.clear()
        assert enricher.entry_count == 0
        assert enricher.lookup("1.2.3.4") is None

    def test_enrich_event_adds_threat_intel_key(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="test")
        event = {"source_ip": "1.2.3.4", "service": "ssh"}
        enricher.enrich_event(event)
        assert "threat_intel" in event
        assert event["threat_intel"] is not None

    def test_enrich_event_none_when_no_match(self):
        enricher = ThreatIntelEnricher()
        event = {"source_ip": "9.9.9.9"}
        enricher.enrich_event(event)
        assert event["threat_intel"] is None

    def test_enrich_event_uses_src_ip_fallback(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="test")
        event = {"src_ip": "1.2.3.4"}
        enricher.enrich_event(event)
        assert event["threat_intel"] is not None

    def test_enrich_batch(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="test")
        events = [
            {"source_ip": "1.2.3.4"},
            {"source_ip": "9.9.9.9"},
        ]
        enricher.enrich_batch(events)
        assert events[0]["threat_intel"] is not None
        assert events[1]["threat_intel"] is None

    def test_lookup_batch(self):
        enricher = ThreatIntelEnricher()
        enricher.load_feed_text("1.2.3.4\n", source="test")
        results = enricher.lookup_batch(["1.2.3.4", "9.9.9.9"])
        assert results["1.2.3.4"] is not None
        assert results["9.9.9.9"] is None

    def test_load_csv_feed(self):
        enricher = ThreatIntelEnricher()
        csv = "ip,category,confidence\n1.2.3.4,scanner,85\n"
        count = enricher.load_feed_text(csv, source="csv-source", fmt="csv")
        assert count == 1
        match = enricher.lookup("1.2.3.4")
        assert match is not None
        assert match.confidence == 85

    def test_load_abuseipdb_json(self):
        enricher = ThreatIntelEnricher()
        data = json.dumps({"data": [{"ipAddress": "5.5.5.5", "abuseConfidenceScore": 99}]})
        count = enricher.load_feed_text(data, source="abuseipdb", fmt="abuseipdb_json")
        assert count == 1
        assert enricher.lookup("5.5.5.5") is not None

    def test_load_stix2_json(self):
        enricher = ThreatIntelEnricher()
        bundle = json.dumps({
            "objects": [{
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '6.6.6.6']",
                "labels": ["malware"],
            }]
        })
        count = enricher.load_feed_text(bundle, source="stix", fmt="stix2_json")
        assert count == 1
        assert enricher.lookup("6.6.6.6") is not None

    def test_expire_stale_removes_old_entries(self):
        enricher = ThreatIntelEnricher(default_ttl=0)  # TTL = 0 seconds
        enricher.load_feed_text("1.2.3.4\n", source="test")
        time.sleep(0.01)  # Ensure TTL has passed
        removed = enricher.expire_stale()
        assert removed >= 1
        assert enricher.lookup("1.2.3.4") is None
