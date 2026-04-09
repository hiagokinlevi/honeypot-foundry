"""
Tests for honeypots.geo_alert
==============================
Covers every risk signal (fire / no-fire), score arithmetic, risk-level
boundary conditions, engine configuration options, ASN burst accumulation,
state reset, evaluate_many behaviour, and serialisation helpers.

Run with::

    pytest tests/test_geo_alert.py -v
"""

from __future__ import annotations

import sys
import os

# Allow imports from the project root when running pytest from repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time

import pytest

from honeypots.geo_alert import (
    GeoAlertEngine,
    GeoRecord,
    GeoAlert,
    GeoRiskLevel,
    GeoSignal,
    _ANONYMIZER_KEYWORDS,
    _HOSTING_KEYWORDS,
    _score_to_level,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_engine() -> GeoAlertEngine:
    """Engine with default configuration (high_risk_countries={"KP","IR"})."""
    return GeoAlertEngine()


@pytest.fixture
def wide_engine() -> GeoAlertEngine:
    """Engine with an expanded high_risk_countries set for broad testing."""
    return GeoAlertEngine(high_risk_countries={"RU", "CN", "KP", "IR", "SY"})


@pytest.fixture
def clean_record() -> GeoRecord:
    """A record that should produce zero signals."""
    return GeoRecord(
        ip="203.0.113.1",
        country_code="DE",
        asn=12345,
        asn_name="Deutsche Telekom AG",
        is_tor=False,
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _signal_ids(alert: GeoAlert) -> list:
    return [s.signal_id for s in alert.signals]


# ===========================================================================
# 1. GEO-001 — High-risk country
# ===========================================================================


class TestGeo001:
    def test_fires_for_high_risk_country(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(ip="1.2.3.4", country_code="KP", asn=0, asn_name="")
        alert = default_engine.evaluate(record)
        assert "GEO-001" in _signal_ids(alert)

    def test_score_contribution_is_35(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(ip="1.2.3.4", country_code="IR", asn=0, asn_name="")
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-001")
        assert sig.score_contribution == 35

    def test_does_not_fire_for_safe_country(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(ip="1.2.3.4", country_code="DE", asn=0, asn_name="")
        alert = default_engine.evaluate(record)
        assert "GEO-001" not in _signal_ids(alert)

    def test_empty_country_code_does_not_fire(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(ip="1.2.3.4", country_code="", asn=0, asn_name="")
        alert = default_engine.evaluate(record)
        assert "GEO-001" not in _signal_ids(alert)

    def test_custom_high_risk_countries(self) -> None:
        engine = GeoAlertEngine(high_risk_countries={"RU"})
        record = GeoRecord(ip="5.6.7.8", country_code="RU", asn=0, asn_name="")
        alert = engine.evaluate(record)
        assert "GEO-001" in _signal_ids(alert)

    def test_custom_high_risk_countries_excludes_default(self) -> None:
        # When a custom set is provided it completely replaces the defaults.
        engine = GeoAlertEngine(high_risk_countries={"RU"})
        record = GeoRecord(ip="5.6.7.8", country_code="KP", asn=0, asn_name="")
        alert = engine.evaluate(record)
        assert "GEO-001" not in _signal_ids(alert)

    def test_detail_contains_country_code(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(ip="1.2.3.4", country_code="IR", asn=0, asn_name="")
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-001")
        assert "IR" in sig.detail


# ===========================================================================
# 2. GEO-002 — Hosting / cloud provider ASN
# ===========================================================================


class TestGeo002:
    @pytest.mark.parametrize("keyword", _HOSTING_KEYWORDS)
    def test_fires_for_each_hosting_keyword(
        self, keyword: str, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(
            ip="10.0.0.1",
            country_code="US",
            asn=99999,
            asn_name=f"ACME {keyword.upper()} Networks",
        )
        alert = default_engine.evaluate(record)
        assert "GEO-002" in _signal_ids(alert), f"GEO-002 did not fire for '{keyword}'"

    def test_score_contribution_is_20(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(
            ip="10.0.0.2", country_code="US", asn=100, asn_name="DigitalOcean LLC"
        )
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-002")
        assert sig.score_contribution == 20

    def test_does_not_fire_for_residential_isp(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(
            ip="10.0.0.3",
            country_code="US",
            asn=7922,
            asn_name="Comcast Cable Communications",
        )
        alert = default_engine.evaluate(record)
        assert "GEO-002" not in _signal_ids(alert)

    def test_case_insensitive_match(self, default_engine: GeoAlertEngine) -> None:
        # Keyword matching should be case-insensitive.
        record = GeoRecord(
            ip="10.0.0.4", country_code="US", asn=100, asn_name="HETZNER Online GmbH"
        )
        alert = default_engine.evaluate(record)
        assert "GEO-002" in _signal_ids(alert)

    def test_empty_asn_name_does_not_fire(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(ip="10.0.0.5", country_code="US", asn=100, asn_name="")
        alert = default_engine.evaluate(record)
        assert "GEO-002" not in _signal_ids(alert)


# ===========================================================================
# 3. GEO-003 — Anonymizer / proxy keyword in ASN name
# ===========================================================================


class TestGeo003:
    @pytest.mark.parametrize("keyword", _ANONYMIZER_KEYWORDS)
    def test_fires_for_each_anonymizer_keyword(
        self, keyword: str, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(
            ip="10.0.0.6",
            country_code="US",
            asn=55555,
            asn_name=f"Super {keyword.upper()} Service",
        )
        alert = default_engine.evaluate(record)
        assert "GEO-003" in _signal_ids(alert), (
            f"GEO-003 did not fire for '{keyword}'"
        )

    def test_score_contribution_is_30(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(
            ip="10.0.0.7",
            country_code="US",
            asn=55555,
            asn_name="NordVPN Network AS",
        )
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-003")
        assert sig.score_contribution == 30

    def test_does_not_fire_for_clean_asn_name(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(
            ip="10.0.0.8",
            country_code="US",
            asn=7922,
            asn_name="Comcast Cable Communications",
        )
        alert = default_engine.evaluate(record)
        assert "GEO-003" not in _signal_ids(alert)

    def test_detail_contains_matched_keyword(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(
            ip="10.0.0.9",
            country_code="US",
            asn=55555,
            asn_name="Mullvad VPN AB",
        )
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-003")
        # The detail should reference the matched keyword.
        assert any(kw in sig.detail for kw in _ANONYMIZER_KEYWORDS)


# ===========================================================================
# 4. GEO-004 — Tor exit node
# ===========================================================================


class TestGeo004:
    def test_fires_when_is_tor_true(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(ip="185.220.101.1", country_code="DE", asn=0, asn_name="", is_tor=True)
        alert = default_engine.evaluate(record)
        assert "GEO-004" in _signal_ids(alert)

    def test_fires_when_ip_in_tor_exit_ips_set(self) -> None:
        tor_ips = {"185.220.101.1", "185.220.101.2"}
        engine = GeoAlertEngine(tor_exit_ips=tor_ips)
        record = GeoRecord(ip="185.220.101.1", country_code="DE", asn=0, asn_name="", is_tor=False)
        alert = engine.evaluate(record)
        assert "GEO-004" in _signal_ids(alert)

    def test_alert_is_tor_flag_set_true(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(ip="185.220.101.3", country_code="US", asn=0, asn_name="", is_tor=True)
        alert = default_engine.evaluate(record)
        assert alert.is_tor is True

    def test_does_not_fire_when_is_tor_false_and_not_in_set(
        self, default_engine: GeoAlertEngine
    ) -> None:
        record = GeoRecord(ip="8.8.8.8", country_code="US", asn=0, asn_name="", is_tor=False)
        alert = default_engine.evaluate(record)
        assert "GEO-004" not in _signal_ids(alert)
        assert alert.is_tor is False

    def test_score_contribution_is_40(self, default_engine: GeoAlertEngine) -> None:
        record = GeoRecord(ip="185.220.101.4", country_code="US", asn=0, asn_name="", is_tor=True)
        alert = default_engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-004")
        assert sig.score_contribution == 40

    def test_fires_when_both_is_tor_true_and_in_set(self) -> None:
        # Should fire exactly once even when both conditions are true.
        tor_ips = {"185.220.101.5"}
        engine = GeoAlertEngine(tor_exit_ips=tor_ips)
        record = GeoRecord(ip="185.220.101.5", country_code="US", asn=0, asn_name="", is_tor=True)
        alert = engine.evaluate(record)
        count = _signal_ids(alert).count("GEO-004")
        assert count == 1

    def test_ip_not_in_tor_set_does_not_fire(self) -> None:
        tor_ips = {"185.220.101.1"}
        engine = GeoAlertEngine(tor_exit_ips=tor_ips)
        record = GeoRecord(ip="9.9.9.9", country_code="US", asn=0, asn_name="", is_tor=False)
        alert = engine.evaluate(record)
        assert "GEO-004" not in _signal_ids(alert)


# ===========================================================================
# 5. GEO-005 — ASN burst
# ===========================================================================


class TestGeo005:
    def test_does_not_fire_below_threshold(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=5)
        for i in range(5):
            record = GeoRecord(ip=f"10.0.1.{i}", country_code="US", asn=1111, asn_name="")
            alert = engine.evaluate(record)
        # Exactly at threshold (count == threshold) should NOT fire.
        assert "GEO-005" not in _signal_ids(alert)  # type: ignore[possibly-undefined]

    def test_fires_one_above_threshold(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=5)
        for i in range(6):
            record = GeoRecord(ip=f"10.0.2.{i}", country_code="US", asn=2222, asn_name="")
            alert = engine.evaluate(record)
        assert "GEO-005" in _signal_ids(alert)

    def test_score_contribution_is_25(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=2)
        for i in range(3):
            record = GeoRecord(ip=f"10.0.3.{i}", country_code="US", asn=3333, asn_name="")
            alert = engine.evaluate(record)
        sig = next(s for s in alert.signals if s.signal_id == "GEO-005")
        assert sig.score_contribution == 25

    def test_reset_clears_burst_state(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=3)
        for i in range(4):
            record = GeoRecord(ip=f"10.0.4.{i}", country_code="US", asn=4444, asn_name="")
            engine.evaluate(record)
        engine.reset_asn_counts()
        # After reset, counter is 0; need 4 more hits before burst fires again.
        for i in range(4):
            record = GeoRecord(ip=f"10.0.5.{i}", country_code="US", asn=4444, asn_name="")
            alert = engine.evaluate(record)
        # Count is now 4, threshold is 3 → fires on hit 4.
        assert "GEO-005" in _signal_ids(alert)

    def test_reset_asn_counts_clears_dict(self) -> None:
        engine = GeoAlertEngine()
        record = GeoRecord(ip="10.0.6.1", country_code="US", asn=5555, asn_name="")
        engine.evaluate(record)
        assert engine._asn_counts  # non-empty
        engine.reset_asn_counts()
        assert engine._asn_counts == {}

    def test_zero_asn_does_not_increment(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=0)
        # ASN == 0 means unknown; burst tracking should be skipped.
        record = GeoRecord(ip="10.0.7.1", country_code="US", asn=0, asn_name="")
        alert = engine.evaluate(record)
        assert "GEO-005" not in _signal_ids(alert)
        assert 0 not in engine._asn_counts

    def test_different_asns_tracked_independently(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=2)
        for i in range(3):
            engine.evaluate(GeoRecord(ip=f"10.0.8.{i}", country_code="US", asn=6666, asn_name=""))
        # ASN 7777 should not trigger burst.
        alert = engine.evaluate(GeoRecord(ip="10.0.9.1", country_code="US", asn=7777, asn_name=""))
        assert "GEO-005" not in _signal_ids(alert)


# ===========================================================================
# 6. Risk level threshold boundary tests
# ===========================================================================


class TestRiskLevelThresholds:
    """Boundary tests that directly exercise _score_to_level."""

    def test_score_79_is_high(self) -> None:
        assert _score_to_level(79) == GeoRiskLevel.HIGH

    def test_score_80_is_critical(self) -> None:
        assert _score_to_level(80) == GeoRiskLevel.CRITICAL

    def test_score_100_is_critical(self) -> None:
        assert _score_to_level(100) == GeoRiskLevel.CRITICAL

    def test_score_54_is_medium(self) -> None:
        assert _score_to_level(54) == GeoRiskLevel.MEDIUM

    def test_score_55_is_high(self) -> None:
        assert _score_to_level(55) == GeoRiskLevel.HIGH

    def test_score_34_is_low(self) -> None:
        assert _score_to_level(34) == GeoRiskLevel.LOW

    def test_score_35_is_medium(self) -> None:
        assert _score_to_level(35) == GeoRiskLevel.MEDIUM

    def test_score_14_is_info(self) -> None:
        assert _score_to_level(14) == GeoRiskLevel.INFO

    def test_score_15_is_low(self) -> None:
        assert _score_to_level(15) == GeoRiskLevel.LOW

    def test_score_0_is_info(self) -> None:
        assert _score_to_level(0) == GeoRiskLevel.INFO


# ===========================================================================
# 7. Score capping at 100
# ===========================================================================


class TestScoreCapping:
    def test_score_capped_at_100(self) -> None:
        """All four signal types fire: 35+20+30+40 = 125, capped to 100."""
        tor_ips = {"1.1.1.1"}
        engine = GeoAlertEngine(
            high_risk_countries={"KP"},
            tor_exit_ips=tor_ips,
        )
        record = GeoRecord(
            ip="1.1.1.1",
            country_code="KP",
            asn=99,
            asn_name="NordVPN DigitalOcean AS",
            is_tor=True,
        )
        alert = engine.evaluate(record)
        assert alert.risk_score == 100

    def test_score_not_negative(self, clean_record: GeoRecord) -> None:
        engine = GeoAlertEngine()
        alert = engine.evaluate(clean_record)
        assert alert.risk_score >= 0


# ===========================================================================
# 8. Clean / INFO record
# ===========================================================================


class TestCleanRecord:
    def test_clean_record_has_zero_signals(
        self, default_engine: GeoAlertEngine, clean_record: GeoRecord
    ) -> None:
        alert = default_engine.evaluate(clean_record)
        assert alert.signals == []

    def test_clean_record_score_is_zero(
        self, default_engine: GeoAlertEngine, clean_record: GeoRecord
    ) -> None:
        alert = default_engine.evaluate(clean_record)
        assert alert.risk_score == 0

    def test_clean_record_level_is_info(
        self, default_engine: GeoAlertEngine, clean_record: GeoRecord
    ) -> None:
        alert = default_engine.evaluate(clean_record)
        assert alert.risk_level == GeoRiskLevel.INFO


# ===========================================================================
# 9. Multiple co-firing signals — score accumulation
# ===========================================================================


class TestMultipleSignals:
    def test_geo001_and_geo004_accumulate(self) -> None:
        engine = GeoAlertEngine(high_risk_countries={"KP"})
        record = GeoRecord(
            ip="10.10.10.1", country_code="KP", asn=0, asn_name="", is_tor=True
        )
        alert = engine.evaluate(record)
        # 35 (GEO-001) + 40 (GEO-004) = 75
        assert alert.risk_score == 75
        assert alert.risk_level == GeoRiskLevel.HIGH

    def test_geo002_and_geo003_accumulate(self) -> None:
        engine = GeoAlertEngine()
        # "proton" (anonymizer) + "cloudflare" (hosting) — crafted name triggers both
        record = GeoRecord(
            ip="10.10.10.2",
            country_code="US",
            asn=100,
            asn_name="Cloudflare-ProtonVPN Tunnel AS",
        )
        alert = engine.evaluate(record)
        # 20 (GEO-002) + 30 (GEO-003) = 50
        assert alert.risk_score == 50
        assert alert.risk_level == GeoRiskLevel.MEDIUM

    def test_three_signals_produce_correct_score(self) -> None:
        engine = GeoAlertEngine(high_risk_countries={"IR"})
        record = GeoRecord(
            ip="10.10.10.3",
            country_code="IR",
            asn=200,
            asn_name="DigitalOcean LLC",
            is_tor=True,
        )
        alert = engine.evaluate(record)
        # 35 (GEO-001) + 20 (GEO-002) + 40 (GEO-004) = 95
        assert alert.risk_score == 95
        assert alert.risk_level == GeoRiskLevel.CRITICAL

    def test_signal_count_in_alert_matches(self) -> None:
        engine = GeoAlertEngine(high_risk_countries={"KP"})
        record = GeoRecord(
            ip="10.10.10.4",
            country_code="KP",
            asn=300,
            asn_name="Vultr Holdings LLC",
            is_tor=False,
        )
        alert = engine.evaluate(record)
        # GEO-001 + GEO-002 = 2 signals
        assert len(alert.signals) == 2


# ===========================================================================
# 10. evaluate_many
# ===========================================================================


class TestEvaluateMany:
    def test_returns_same_count_as_input(self) -> None:
        engine = GeoAlertEngine()
        records = [
            GeoRecord(ip=f"192.168.1.{i}", country_code="US", asn=1000, asn_name="")
            for i in range(10)
        ]
        alerts = engine.evaluate_many(records)
        assert len(alerts) == 10

    def test_preserves_order(self) -> None:
        engine = GeoAlertEngine(high_risk_countries={"KP"})
        ips = ["10.1.1.1", "10.1.1.2", "10.1.1.3"]
        records = [
            GeoRecord(ip=ip, country_code="KP", asn=0, asn_name="") for ip in ips
        ]
        alerts = engine.evaluate_many(records)
        assert [a.ip for a in alerts] == ips

    def test_asn_burst_accumulates_across_evaluate_many(self) -> None:
        engine = GeoAlertEngine(asn_burst_threshold=3)
        records = [
            GeoRecord(ip=f"172.16.0.{i}", country_code="US", asn=8888, asn_name="")
            for i in range(5)
        ]
        alerts = engine.evaluate_many(records)
        # Records 0-3: counts 1-4, burst fires when count > 3 → records 4 & 5 fire.
        burst_fired = ["GEO-005" in _signal_ids(a) for a in alerts]
        assert burst_fired[3] is True  # 4th connection (count=4) exceeds threshold 3
        assert burst_fired[4] is True

    def test_evaluate_many_empty_list(self) -> None:
        engine = GeoAlertEngine()
        assert engine.evaluate_many([]) == []

    def test_evaluate_many_single_element(self) -> None:
        engine = GeoAlertEngine()
        record = GeoRecord(ip="1.2.3.4", country_code="US", asn=0, asn_name="")
        alerts = engine.evaluate_many([record])
        assert len(alerts) == 1
        assert alerts[0].ip == "1.2.3.4"


# ===========================================================================
# 11. GeoAlert serialisation helpers
# ===========================================================================


class TestGeoAlertSerialization:
    def _make_alert(self) -> GeoAlert:
        engine = GeoAlertEngine(high_risk_countries={"KP"})
        record = GeoRecord(
            ip="198.51.100.5",
            country_code="KP",
            asn=500,
            asn_name="DigitalOcean LLC",
            is_tor=True,
        )
        return engine.evaluate(record)

    def test_to_dict_returns_dict(self) -> None:
        alert = self._make_alert()
        assert isinstance(alert.to_dict(), dict)

    def test_to_dict_risk_level_is_string(self) -> None:
        alert = self._make_alert()
        d = alert.to_dict()
        assert isinstance(d["risk_level"], str)

    def test_to_dict_signals_is_list_of_dicts(self) -> None:
        alert = self._make_alert()
        d = alert.to_dict()
        assert isinstance(d["signals"], list)
        for sig in d["signals"]:
            assert isinstance(sig, dict)
            assert "signal_id" in sig
            assert "title" in sig
            assert "score_contribution" in sig
            assert "detail" in sig

    def test_to_dict_required_keys_present(self) -> None:
        alert = self._make_alert()
        d = alert.to_dict()
        for key in ("ip", "country_code", "risk_score", "risk_level", "signals", "is_tor", "generated_at"):
            assert key in d

    def test_to_dict_ip_matches(self) -> None:
        alert = self._make_alert()
        assert alert.to_dict()["ip"] == "198.51.100.5"

    def test_summary_format(self) -> None:
        alert = self._make_alert()
        summary = alert.summary()
        assert "198.51.100.5" in summary
        assert "KP" in summary
        assert "risk=" in summary
        assert "signal(s)" in summary

    def test_summary_signal_count(self) -> None:
        alert = self._make_alert()
        expected = f"{len(alert.signals)} signal(s)"
        assert expected in alert.summary()

    def test_generated_at_is_recent_float(self) -> None:
        before = time.time()
        engine = GeoAlertEngine()
        alert = engine.evaluate(GeoRecord(ip="1.1.1.2", country_code="US", asn=0, asn_name=""))
        after = time.time()
        assert isinstance(alert.generated_at, float)
        assert before <= alert.generated_at <= after


# ===========================================================================
# 12. GeoRiskLevel enum values
# ===========================================================================


class TestGeoRiskLevelEnum:
    def test_all_levels_present(self) -> None:
        levels = {l.value for l in GeoRiskLevel}
        assert levels == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


# ===========================================================================
# 13. GeoRecord defaults
# ===========================================================================


class TestGeoRecordDefaults:
    def test_default_country_code_empty(self) -> None:
        r = GeoRecord(ip="1.2.3.4")
        assert r.country_code == ""

    def test_default_asn_zero(self) -> None:
        r = GeoRecord(ip="1.2.3.4")
        assert r.asn == 0

    def test_default_asn_name_empty(self) -> None:
        r = GeoRecord(ip="1.2.3.4")
        assert r.asn_name == ""

    def test_default_is_tor_false(self) -> None:
        r = GeoRecord(ip="1.2.3.4")
        assert r.is_tor is False

    def test_default_metadata_is_empty_dict(self) -> None:
        r = GeoRecord(ip="1.2.3.4")
        assert r.metadata == {}

    def test_metadata_not_shared_between_instances(self) -> None:
        r1 = GeoRecord(ip="1.1.1.1")
        r2 = GeoRecord(ip="2.2.2.2")
        r1.metadata["key"] = "value"
        assert "key" not in r2.metadata
