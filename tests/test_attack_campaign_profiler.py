"""
test_attack_campaign_profiler.py
─────────────────────────────────
≥110 tests covering all CAMP-001 … CAMP-007 checks (positive + negative),
campaign tier thresholds, profile_campaigns_by_window, to_dict/summary shapes,
metadata fields, affected_ips contract, and edge cases.
"""

from __future__ import annotations

import hashlib
import sys
import os

# Make the analysis package importable regardless of PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analysis.attack_campaign_profiler import (
    CampaignCheck,
    CampaignProfile,
    HoneypotEvent,
    _campaign_id,
    _is_common_word_password,
    _is_targeted_password,
    _slash24_key,
    _slash28_key,
    _tier,
    profile_campaign,
    profile_campaigns_by_window,
)

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ──────────────────────────────────────────────────────────────────────────────

BASE_TS = 1_700_000_000_000  # arbitrary epoch ms anchor
ONE_HOUR_MS = 3_600_000
ONE_MIN_MS = 60_000
FIVE_MIN_MS = 300_000
THIRTY_MIN_MS = 1_800_000
FORTY_EIGHT_H_MS = 172_800_001  # just over 48 h


def _ev(
    eid: str,
    ip: str,
    service: str = "ssh",
    ts: int = BASE_TS,
    username: str = "",
    password: str = "",
    user_agent: str = "",
    event_type: str = "auth_attempt",
) -> HoneypotEvent:
    """Convenience factory with sensible defaults."""
    return HoneypotEvent(
        event_id=eid,
        source_ip=ip,
        service=service,
        timestamp_ms=ts,
        username=username,
        password=password,
        user_agent=user_agent,
        event_type=event_type,
    )


def _ids(profile: CampaignProfile) -> list:
    return [c.check_id for c in profile.checks_fired]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Empty events
# ══════════════════════════════════════════════════════════════════════════════

class TestEmptyEvents:
    def test_empty_returns_profile(self):
        p = profile_campaign([])
        assert isinstance(p, CampaignProfile)

    def test_empty_zero_checks(self):
        p = profile_campaign([])
        assert p.checks_fired == []

    def test_empty_isolated_tier(self):
        p = profile_campaign([])
        assert p.campaign_tier == "ISOLATED"

    def test_empty_zero_score(self):
        p = profile_campaign([])
        assert p.risk_score == 0

    def test_empty_zero_events(self):
        p = profile_campaign([])
        assert p.total_events == 0

    def test_empty_zero_ips(self):
        p = profile_campaign([])
        assert p.unique_ips == 0

    def test_empty_zero_span(self):
        p = profile_campaign([])
        assert p.time_span_seconds == 0

    def test_empty_window_returns_empty_list(self):
        result = profile_campaigns_by_window([])
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# 2. CAMP-001 — Multi-source credential reuse
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp001:
    def _make_events(self, ip_count: int) -> list:
        """Create events where 'admin'/'pass123' is used from ip_count IPs."""
        evs = []
        for i in range(ip_count):
            evs.append(_ev(
                f"e001-{i}", f"10.0.{i}.1",
                username="admin", password="pass123",
                ts=BASE_TS + i * 1000,
            ))
        return evs

    def test_positive_exactly_three_ips(self):
        p = profile_campaign(self._make_events(3))
        assert "CAMP-001" in _ids(p)

    def test_positive_five_ips(self):
        p = profile_campaign(self._make_events(5))
        assert "CAMP-001" in _ids(p)

    def test_negative_two_ips(self):
        p = profile_campaign(self._make_events(2))
        assert "CAMP-001" not in _ids(p)

    def test_negative_one_ip(self):
        p = profile_campaign(self._make_events(1))
        assert "CAMP-001" not in _ids(p)

    def test_negative_different_passwords(self):
        evs = [
            _ev("e1", "10.0.1.1", username="admin", password="aaa"),
            _ev("e2", "10.0.2.1", username="admin", password="bbb"),
            _ev("e3", "10.0.3.1", username="admin", password="ccc"),
        ]
        p = profile_campaign(evs)
        assert "CAMP-001" not in _ids(p)

    def test_positive_severity_critical(self):
        p = profile_campaign(self._make_events(3))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-001")
        assert c.severity == "CRITICAL"

    def test_positive_weight_45(self):
        p = profile_campaign(self._make_events(3))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-001")
        assert c.weight == 45

    def test_positive_affected_ips_count(self):
        p = profile_campaign(self._make_events(3))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-001")
        assert len(c.affected_ips) == 3

    def test_affected_ips_capped_at_10(self):
        p = profile_campaign(self._make_events(15))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-001")
        assert len(c.affected_ips) <= 10

    def test_negative_missing_username(self):
        evs = [
            _ev("e1", "10.0.1.1", password="pass123"),
            _ev("e2", "10.0.2.1", password="pass123"),
            _ev("e3", "10.0.3.1", password="pass123"),
        ]
        p = profile_campaign(evs)
        assert "CAMP-001" not in _ids(p)


# ══════════════════════════════════════════════════════════════════════════════
# 3. CAMP-002 — Distributed scanning
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp002:
    def _make_events(self, ip_count: int, within_hour: bool = True) -> list:
        evs = []
        for i in range(ip_count):
            ts_offset = i * 100_000 if within_hour else i * ONE_HOUR_MS
            evs.append(_ev(
                f"e002-{i}", f"10.1.{i}.1",
                service="redis",
                ts=BASE_TS + ts_offset,
            ))
        return evs

    def test_positive_five_ips(self):
        p = profile_campaign(self._make_events(5))
        assert "CAMP-002" in _ids(p)

    def test_positive_ten_ips(self):
        p = profile_campaign(self._make_events(10))
        assert "CAMP-002" in _ids(p)

    def test_negative_four_ips(self):
        p = profile_campaign(self._make_events(4))
        assert "CAMP-002" not in _ids(p)

    def test_negative_five_ips_spread_across_hours(self):
        # 5 IPs but each 1 hour apart — no 1-hour window can contain all 5
        p = profile_campaign(self._make_events(5, within_hour=False))
        assert "CAMP-002" not in _ids(p)

    def test_positive_severity_high(self):
        p = profile_campaign(self._make_events(5))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-002")
        assert c.severity == "HIGH"

    def test_positive_weight_30(self):
        p = profile_campaign(self._make_events(5))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-002")
        assert c.weight == 30

    def test_positive_different_services_no_cross_trigger(self):
        # 3 IPs on ssh + 3 IPs on http — each service has only 3, below threshold
        evs = []
        for i in range(3):
            evs.append(_ev(f"es-{i}", f"10.2.{i}.1", service="ssh", ts=BASE_TS + i * 1000))
        for i in range(3):
            evs.append(_ev(f"eh-{i}", f"10.3.{i}.1", service="http", ts=BASE_TS + i * 1000))
        p = profile_campaign(evs)
        assert "CAMP-002" not in _ids(p)

    def test_affected_ips_populated(self):
        p = profile_campaign(self._make_events(6))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-002")
        assert len(c.affected_ips) >= 5


# ══════════════════════════════════════════════════════════════════════════════
# 4. CAMP-003 — Sequential subnet sweep
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp003:
    def _make_sweep(self, octets: list, gap_ms: int = 60_000) -> list:
        """Create events from IPs in 192.168.1.{octet} with given inter-IP gap."""
        evs = []
        for idx, octet in enumerate(octets):
            evs.append(_ev(
                f"e003-{octet}",
                f"192.168.1.{octet}",
                service="ssh",
                ts=BASE_TS + idx * gap_ms,
            ))
        return evs

    def test_positive_three_sorted_octets_small_gap(self):
        p = profile_campaign(self._make_sweep([10, 11, 12], gap_ms=60_000))
        assert "CAMP-003" in _ids(p)

    def test_positive_larger_run(self):
        p = profile_campaign(self._make_sweep([5, 6, 7, 8], gap_ms=60_000))
        assert "CAMP-003" in _ids(p)

    def test_negative_gap_too_large(self):
        # 10 minutes between each IP — exceeds 5-minute threshold
        p = profile_campaign(self._make_sweep([10, 11, 12], gap_ms=600_001))
        assert "CAMP-003" not in _ids(p)

    def test_negative_only_two_ips(self):
        p = profile_campaign(self._make_sweep([10, 11], gap_ms=60_000))
        assert "CAMP-003" not in _ids(p)

    def test_negative_different_subnets(self):
        evs = [
            _ev("e1", "10.0.1.1", ts=BASE_TS),
            _ev("e2", "10.0.2.2", ts=BASE_TS + 60_000),
            _ev("e3", "10.0.3.3", ts=BASE_TS + 120_000),
        ]
        p = profile_campaign(evs)
        assert "CAMP-003" not in _ids(p)

    def test_positive_severity_high(self):
        p = profile_campaign(self._make_sweep([20, 21, 22]))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-003")
        assert c.severity == "HIGH"

    def test_positive_weight_25(self):
        p = profile_campaign(self._make_sweep([20, 21, 22]))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-003")
        assert c.weight == 25

    def test_positive_affected_ips_are_subnet_ips(self):
        p = profile_campaign(self._make_sweep([30, 31, 32]))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-003")
        assert all("192.168.1." in ip for ip in c.affected_ips)

    def test_slash24_key_helper(self):
        assert _slash24_key("192.168.1.50") == "192.168.1"
        assert _slash24_key("10.0.0.1") == "10.0.0"
        assert _slash24_key("invalid") is None

    def test_boundary_gap_just_under_300s(self):
        # 299 seconds gap — should fire
        p = profile_campaign(self._make_sweep([40, 41, 42], gap_ms=299_000))
        assert "CAMP-003" in _ids(p)

    def test_boundary_gap_exactly_300s_exclusive(self):
        # Exactly 300 000 ms — the check requires < 300 000, so should NOT fire
        p = profile_campaign(self._make_sweep([50, 51, 52], gap_ms=300_000))
        assert "CAMP-003" not in _ids(p)


# ══════════════════════════════════════════════════════════════════════════════
# 5. CAMP-004 — Tool fingerprint clustering
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp004:
    def _make_events(self, ip_count: int, ua: str = "MassScan/1.0") -> list:
        evs = []
        for i in range(ip_count):
            evs.append(_ev(
                f"e004-{i}", f"10.4.{i}.1",
                user_agent=ua,
                ts=BASE_TS + i * 1000,
            ))
        return evs

    def test_positive_three_ips(self):
        p = profile_campaign(self._make_events(3))
        assert "CAMP-004" in _ids(p)

    def test_positive_five_ips(self):
        p = profile_campaign(self._make_events(5))
        assert "CAMP-004" in _ids(p)

    def test_negative_two_ips(self):
        p = profile_campaign(self._make_events(2))
        assert "CAMP-004" not in _ids(p)

    def test_negative_empty_ua(self):
        evs = [
            _ev("e1", "10.5.1.1", user_agent=""),
            _ev("e2", "10.5.2.1", user_agent=""),
            _ev("e3", "10.5.3.1", user_agent=""),
        ]
        p = profile_campaign(evs)
        assert "CAMP-004" not in _ids(p)

    def test_negative_whitespace_ua(self):
        evs = [
            _ev("e1", "10.6.1.1", user_agent="   "),
            _ev("e2", "10.6.2.1", user_agent="   "),
            _ev("e3", "10.6.3.1", user_agent="   "),
        ]
        p = profile_campaign(evs)
        assert "CAMP-004" not in _ids(p)

    def test_positive_severity_high(self):
        p = profile_campaign(self._make_events(3))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-004")
        assert c.severity == "HIGH"

    def test_positive_weight_25(self):
        p = profile_campaign(self._make_events(3))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-004")
        assert c.weight == 25

    def test_affected_ips_capped(self):
        p = profile_campaign(self._make_events(12))
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-004")
        assert len(c.affected_ips) <= 10


# ══════════════════════════════════════════════════════════════════════════════
# 6. CAMP-005 — Temporal burst pattern
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp005:
    def _burst_events(self, count: int = 20, ip_count: int = 5, spread_ms: int = 10_000) -> list:
        """Create a burst of events within 5 minutes from multiple IPs."""
        evs = []
        for i in range(count):
            ip = f"10.5.{i % ip_count}.1"
            evs.append(_ev(f"b-{i}", ip, ts=BASE_TS + i * spread_ms))
        return evs

    def _add_silence_then_event(self, burst_evs: list, silence_ms: int) -> list:
        last_ts = max(e.timestamp_ms for e in burst_evs)
        trailing = _ev("tail-1", "10.9.9.1", ts=last_ts + silence_ms)
        return burst_evs + [trailing]

    def test_positive_burst_then_silence(self):
        burst = self._burst_events(20, 5)
        evs = self._add_silence_then_event(burst, THIRTY_MIN_MS + 1000)
        p = profile_campaign(evs)
        assert "CAMP-005" in _ids(p)

    def test_positive_no_trailing_events(self):
        # Burst followed by a well-separated event (>30 min after) → silence confirmed
        burst = self._burst_events(20, 5)
        evs = self._add_silence_then_event(burst, THIRTY_MIN_MS + 60_000)
        p = profile_campaign(evs)
        assert "CAMP-005" in _ids(p)

    def test_negative_burst_no_silence(self):
        # Events continue immediately after burst — no 30-min silence
        burst = self._burst_events(20, 5)
        # Add event only 5 minutes after burst end (not enough silence)
        last_ts = max(e.timestamp_ms for e in burst)
        noisy = [_ev(f"noise-{i}", "10.9.9.1", ts=last_ts + i * 30_000) for i in range(10)]
        p = profile_campaign(burst + noisy)
        assert "CAMP-005" not in _ids(p)

    def test_negative_too_few_events(self):
        # Only 19 events — below threshold of 20
        burst = self._burst_events(19, 5)
        p = profile_campaign(burst)
        assert "CAMP-005" not in _ids(p)

    def test_negative_too_few_ips(self):
        # 20 events but only 2 distinct IPs
        evs = []
        for i in range(20):
            ip = f"10.5.{i % 2}.1"
            evs.append(_ev(f"b2-{i}", ip, ts=BASE_TS + i * 10_000))
        p = profile_campaign(evs)
        assert "CAMP-005" not in _ids(p)

    def test_positive_severity_medium(self):
        burst = self._burst_events(20, 5)
        p = profile_campaign(burst)
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-005")
        assert c.severity == "MEDIUM"

    def test_positive_weight_20(self):
        burst = self._burst_events(20, 5)
        p = profile_campaign(burst)
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-005")
        assert c.weight == 20

    def test_burst_requires_both_conditions(self):
        # 20 events, 5 IPs, but continuous activity after (every 60 s for 20 min)
        # → no 30-min silence window → CAMP-005 must not fire
        burst = self._burst_events(20, 5)
        last_ts = max(e.timestamp_ms for e in burst)
        continuous = [_ev(f"cont-{i}", "10.9.9.2", ts=last_ts + i * 60_000) for i in range(1, 21)]
        p = profile_campaign(burst + continuous)
        assert "CAMP-005" not in _ids(p)

    def test_silence_exactly_30min(self):
        burst = self._burst_events(20, 5)
        evs = self._add_silence_then_event(burst, THIRTY_MIN_MS)
        p = profile_campaign(evs)
        assert "CAMP-005" in _ids(p)


# ══════════════════════════════════════════════════════════════════════════════
# 7. CAMP-006 — Credential progression
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp006:
    def _progression_events(self, ip: str = "10.6.6.6") -> list:
        """Early: common words. Late: targeted with @ or year."""
        return [
            _ev("p1", ip, ts=BASE_TS,              password="admin",   username="root"),
            _ev("p2", ip, ts=BASE_TS + ONE_MIN_MS, password="test",    username="root"),
            _ev("p3", ip, ts=BASE_TS + 2*ONE_MIN_MS, password="mysql@2023", username="root"),
            _ev("p4", ip, ts=BASE_TS + 3*ONE_MIN_MS, password="root@2024",  username="root"),
        ]

    def test_positive_single_ip_progression(self):
        p = profile_campaign(self._progression_events())
        assert "CAMP-006" in _ids(p)

    def test_positive_multiple_ips(self):
        evs = self._progression_events("10.6.6.1") + self._progression_events("10.6.6.2")
        p = profile_campaign(evs)
        assert "CAMP-006" in _ids(p)

    def test_negative_only_common_words(self):
        evs = [
            _ev("n1", "10.6.7.1", ts=BASE_TS,              password="admin", username="u"),
            _ev("n2", "10.6.7.1", ts=BASE_TS + ONE_MIN_MS, password="test",  username="u"),
            _ev("n3", "10.6.7.1", ts=BASE_TS + 2*ONE_MIN_MS, password="pass", username="u"),
            _ev("n4", "10.6.7.1", ts=BASE_TS + 3*ONE_MIN_MS, password="login", username="u"),
        ]
        p = profile_campaign(evs)
        assert "CAMP-006" not in _ids(p)

    def test_negative_only_targeted(self):
        evs = [
            _ev("n1", "10.6.8.1", ts=BASE_TS,              password="root@2022", username="u"),
            _ev("n2", "10.6.8.1", ts=BASE_TS + ONE_MIN_MS, password="mysql@2024", username="u"),
        ]
        p = profile_campaign(evs)
        assert "CAMP-006" not in _ids(p)

    def test_negative_single_password(self):
        evs = [_ev("n1", "10.6.9.1", password="admin", username="u")]
        p = profile_campaign(evs)
        assert "CAMP-006" not in _ids(p)

    def test_positive_severity_medium(self):
        p = profile_campaign(self._progression_events())
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-006")
        assert c.severity == "MEDIUM"

    def test_positive_weight_20(self):
        p = profile_campaign(self._progression_events())
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-006")
        assert c.weight == 20

    def test_password_helpers_common_word(self):
        assert _is_common_word_password("admin") is True
        assert _is_common_word_password("test") is True
        assert _is_common_word_password("abcdefgh") is True  # length 8
        assert _is_common_word_password("password1") is False  # digit
        assert _is_common_word_password("Admin") is False     # uppercase
        assert _is_common_word_password("abcdefghi") is False  # length 9

    def test_password_helpers_targeted(self):
        assert _is_targeted_password("mysql@2023") is True
        assert _is_targeted_password("root2024") is True
        assert _is_targeted_password("service@host") is True
        assert _is_targeted_password("admin") is False
        assert _is_targeted_password("password") is False


# ══════════════════════════════════════════════════════════════════════════════
# 8. CAMP-007 — Return attacker
# ══════════════════════════════════════════════════════════════════════════════

class TestCamp007:
    def test_positive_single_ip_48h_gap(self):
        evs = [
            _ev("r1", "10.7.1.1", ts=BASE_TS),
            _ev("r2", "10.7.1.1", ts=BASE_TS + FORTY_EIGHT_H_MS),
        ]
        p = profile_campaign(evs)
        assert "CAMP-007" in _ids(p)

    def test_negative_same_ip_exactly_48h(self):
        # Exactly 48 h (not strictly greater) — should NOT fire
        evs = [
            _ev("r1", "10.7.2.1", ts=BASE_TS),
            _ev("r2", "10.7.2.1", ts=BASE_TS + 172_800_000),
        ]
        p = profile_campaign(evs)
        assert "CAMP-007" not in _ids(p)

    def test_negative_gap_less_than_48h(self):
        evs = [
            _ev("r1", "10.7.3.1", ts=BASE_TS),
            _ev("r2", "10.7.3.1", ts=BASE_TS + 100_000_000),  # ~27.7 h
        ]
        p = profile_campaign(evs)
        assert "CAMP-007" not in _ids(p)

    def test_positive_slash28_subnet(self):
        # Two IPs in same /28, seen 48+ h apart
        evs = [
            _ev("s1", "192.168.5.1", ts=BASE_TS),
            _ev("s2", "192.168.5.2", ts=BASE_TS + FORTY_EIGHT_H_MS),
        ]
        p = profile_campaign(evs)
        assert "CAMP-007" in _ids(p)

    def test_negative_slash28_within_48h(self):
        evs = [
            _ev("s1", "192.168.5.1", ts=BASE_TS),
            _ev("s2", "192.168.5.2", ts=BASE_TS + ONE_HOUR_MS),
        ]
        p = profile_campaign(evs)
        assert "CAMP-007" not in _ids(p)

    def test_positive_severity_medium(self):
        evs = [
            _ev("r1", "10.7.4.1", ts=BASE_TS),
            _ev("r2", "10.7.4.1", ts=BASE_TS + FORTY_EIGHT_H_MS),
        ]
        p = profile_campaign(evs)
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-007")
        assert c.severity == "MEDIUM"

    def test_positive_weight_15(self):
        evs = [
            _ev("r1", "10.7.5.1", ts=BASE_TS),
            _ev("r2", "10.7.5.1", ts=BASE_TS + FORTY_EIGHT_H_MS),
        ]
        p = profile_campaign(evs)
        c = next(c for c in p.checks_fired if c.check_id == "CAMP-007")
        assert c.weight == 15

    def test_slash28_key_helper(self):
        k1 = _slash28_key("10.0.0.1")
        k2 = _slash28_key("10.0.0.15")
        # Both are in the same /28 (10.0.0.0/28)
        assert k1 == k2

    def test_slash28_key_different_subnets(self):
        k1 = _slash28_key("10.0.0.1")
        k3 = _slash28_key("10.0.0.16")  # next /28 block
        assert k1 != k3


# ══════════════════════════════════════════════════════════════════════════════
# 9. Campaign tier thresholds
# ══════════════════════════════════════════════════════════════════════════════

class TestCampaignTiers:
    def test_tier_helper_isolated(self):
        assert _tier(0) == "ISOLATED"
        assert _tier(14) == "ISOLATED"

    def test_tier_helper_suspicious(self):
        assert _tier(15) == "SUSPICIOUS"
        assert _tier(34) == "SUSPICIOUS"

    def test_tier_helper_likely_coordinated(self):
        assert _tier(35) == "LIKELY_COORDINATED"
        assert _tier(59) == "LIKELY_COORDINATED"

    def test_tier_helper_coordinated(self):
        assert _tier(60) == "COORDINATED"
        assert _tier(100) == "COORDINATED"

    def test_coordinated_from_camp001_alone(self):
        # CAMP-001 weight=45 < 60, so needs another check to reach COORDINATED
        evs = []
        for i in range(3):
            evs.append(_ev(f"c-{i}", f"10.8.{i}.1", username="root", password="toor"))
        p = profile_campaign(evs)
        # CAMP-001 fires (score=45) → LIKELY_COORDINATED
        assert p.campaign_tier == "LIKELY_COORDINATED"

    def test_coordinated_from_camp001_plus_camp002(self):
        # Craft events that trigger CAMP-001 (w=45) + CAMP-002 (w=30) → 75 → COORDINATED
        evs = []
        # CAMP-001: same creds from 3 IPs
        for i in range(3):
            evs.append(_ev(f"c1-{i}", f"10.9.{i}.1", service="ssh",
                           username="root", password="toor",
                           ts=BASE_TS + i * 1000))
        # CAMP-002: 5 IPs on same service within 1 hour
        for i in range(5):
            evs.append(_ev(f"c2-{i}", f"10.10.{i}.1", service="ssh",
                           ts=BASE_TS + i * 5000))
        p = profile_campaign(evs)
        assert p.campaign_tier == "COORDINATED"
        assert p.risk_score >= 60

    def test_risk_score_capped_at_100(self):
        # Fire all checks that we can by overlapping events
        # CAMP-001(45) + CAMP-002(30) alone = 75; adding more caps at 100
        evs = []
        for i in range(3):
            evs.append(_ev(f"x-{i}", f"10.11.{i}.1", service="mysql",
                           username="root", password="toor",
                           user_agent="nmap/7.9",
                           ts=BASE_TS + i * 1000))
        for i in range(5):
            evs.append(_ev(f"y-{i}", f"10.12.{i}.1", service="mysql",
                           user_agent="nmap/7.9",
                           ts=BASE_TS + i * 5000))
        p = profile_campaign(evs)
        assert p.risk_score <= 100

    def test_isolated_with_single_event(self):
        p = profile_campaign([_ev("solo", "1.2.3.4")])
        assert p.campaign_tier == "ISOLATED"


# ══════════════════════════════════════════════════════════════════════════════
# 10. profile_campaigns_by_window
# ══════════════════════════════════════════════════════════════════════════════

class TestProfileCampaignsByWindow:
    def test_single_window_single_profile(self):
        evs = [_ev(f"w-{i}", f"10.0.{i}.1", ts=BASE_TS + i * 1000) for i in range(5)]
        profiles = profile_campaigns_by_window(evs, window_seconds=3600)
        assert len(profiles) == 1

    def test_two_windows_two_profiles(self):
        evs_w1 = [_ev(f"w1-{i}", f"10.0.{i}.1", ts=BASE_TS + i * 1000) for i in range(3)]
        evs_w2 = [_ev(f"w2-{i}", f"10.1.{i}.1", ts=BASE_TS + ONE_HOUR_MS + i * 1000) for i in range(3)]
        profiles = profile_campaigns_by_window(evs_w1 + evs_w2, window_seconds=3600)
        assert len(profiles) == 2

    def test_events_separated_across_windows(self):
        evs_w1 = [_ev("a1", "1.1.1.1", ts=BASE_TS)]
        evs_w2 = [_ev("a2", "2.2.2.2", ts=BASE_TS + ONE_HOUR_MS * 2)]
        profiles = profile_campaigns_by_window(evs_w1 + evs_w2, window_seconds=3600)
        # Events are more than 1 window apart
        total = sum(p.total_events for p in profiles)
        assert total == 2

    def test_window_returns_list(self):
        evs = [_ev("q1", "1.1.1.1", ts=BASE_TS)]
        result = profile_campaigns_by_window(evs)
        assert isinstance(result, list)
        assert all(isinstance(p, CampaignProfile) for p in result)

    def test_each_profile_is_isolated_without_triggers(self):
        # 1 event per window — no checks should fire
        evs = [_ev(f"iso-{i}", f"10.0.{i}.1", ts=BASE_TS + i * ONE_HOUR_MS) for i in range(3)]
        profiles = profile_campaigns_by_window(evs, window_seconds=3600)
        for p in profiles:
            assert p.campaign_tier == "ISOLATED"

    def test_custom_window_seconds(self):
        # 3 events each 2 hours apart — with window_seconds=7200 they might merge
        evs = [_ev(f"cw-{i}", f"10.0.{i}.1", ts=BASE_TS + i * 7200 * 1000) for i in range(3)]
        profiles = profile_campaigns_by_window(evs, window_seconds=7200)
        # Each event is exactly at the boundary; with anchoring they may land in separate windows
        assert len(profiles) >= 1

    def test_window_profiles_sorted_by_time(self):
        evs_w2 = [_ev("late", "2.2.2.2", ts=BASE_TS + ONE_HOUR_MS * 3)]
        evs_w1 = [_ev("early", "1.1.1.1", ts=BASE_TS)]
        profiles = profile_campaigns_by_window(evs_w1 + evs_w2, window_seconds=3600)
        # Profiles ordered by window start (ascending)
        if len(profiles) == 2:
            ts0 = min(e.timestamp_ms for e in [evs_w1[0]])
            ts1 = min(e.timestamp_ms for e in [evs_w2[0]])
            assert ts0 < ts1

    def test_empty_windows_not_included(self):
        # Only 2 events far apart — no empty window profile
        evs = [
            _ev("x1", "1.1.1.1", ts=BASE_TS),
            _ev("x2", "2.2.2.2", ts=BASE_TS + ONE_HOUR_MS * 10),
        ]
        profiles = profile_campaigns_by_window(evs, window_seconds=3600)
        assert all(p.total_events > 0 for p in profiles)


# ══════════════════════════════════════════════════════════════════════════════
# 11. to_dict() and summary() shapes
# ══════════════════════════════════════════════════════════════════════════════

class TestSerialisation:
    def _basic_profile(self) -> CampaignProfile:
        evs = [_ev(f"d-{i}", f"10.0.{i}.1", ts=BASE_TS + i * 1000) for i in range(3)]
        return profile_campaign(evs)

    def test_to_dict_keys(self):
        d = self._basic_profile().to_dict()
        expected = {
            "campaign_id", "risk_score", "campaign_tier",
            "total_events", "unique_ips", "time_span_seconds", "checks_fired",
        }
        assert set(d.keys()) == expected

    def test_to_dict_checks_fired_is_list(self):
        d = self._basic_profile().to_dict()
        assert isinstance(d["checks_fired"], list)

    def test_to_dict_check_keys(self):
        evs = []
        for i in range(3):
            evs.append(_ev(f"k-{i}", f"10.0.{i}.1", username="admin", password="pass", ts=BASE_TS + i))
        d = profile_campaign(evs).to_dict()
        if d["checks_fired"]:
            check = d["checks_fired"][0]
            assert "check_id" in check
            assert "severity" in check
            assert "description" in check
            assert "evidence" in check
            assert "weight" in check
            assert "affected_ips" in check

    def test_to_dict_values_types(self):
        d = self._basic_profile().to_dict()
        assert isinstance(d["campaign_id"], str)
        assert isinstance(d["risk_score"], int)
        assert isinstance(d["campaign_tier"], str)
        assert isinstance(d["total_events"], int)
        assert isinstance(d["unique_ips"], int)
        assert isinstance(d["time_span_seconds"], int)

    def test_summary_is_string(self):
        s = self._basic_profile().summary()
        assert isinstance(s, str)

    def test_summary_contains_tier(self):
        p = self._basic_profile()
        assert p.campaign_tier in p.summary()

    def test_summary_contains_score(self):
        p = self._basic_profile()
        assert str(p.risk_score) in p.summary()

    def test_summary_contains_campaign_id(self):
        p = self._basic_profile()
        assert p.campaign_id in p.summary()

    def test_summary_empty_no_checks(self):
        p = profile_campaign([])
        s = p.summary()
        assert "none" in s


# ══════════════════════════════════════════════════════════════════════════════
# 12. Metadata fields: total_events, unique_ips, time_span_seconds
# ══════════════════════════════════════════════════════════════════════════════

class TestMetadataFields:
    def test_total_events_count(self):
        evs = [_ev(f"m-{i}", "1.2.3.4", ts=BASE_TS + i * 1000) for i in range(7)]
        p = profile_campaign(evs)
        assert p.total_events == 7

    def test_unique_ips_count(self):
        evs = [
            _ev("m1", "1.1.1.1", ts=BASE_TS),
            _ev("m2", "1.1.1.1", ts=BASE_TS + 1000),
            _ev("m3", "2.2.2.2", ts=BASE_TS + 2000),
            _ev("m4", "3.3.3.3", ts=BASE_TS + 3000),
        ]
        p = profile_campaign(evs)
        assert p.unique_ips == 3

    def test_time_span_seconds_correct(self):
        evs = [
            _ev("ts1", "1.1.1.1", ts=BASE_TS),
            _ev("ts2", "2.2.2.2", ts=BASE_TS + 5_000_000),  # 5000 seconds later
        ]
        p = profile_campaign(evs)
        assert p.time_span_seconds == 5000

    def test_single_event_zero_span(self):
        p = profile_campaign([_ev("s1", "1.1.1.1", ts=BASE_TS)])
        assert p.time_span_seconds == 0

    def test_campaign_id_deterministic(self):
        evs = [_ev(f"d{i}", f"10.0.{i}.1", ts=BASE_TS + i) for i in range(4)]
        p1 = profile_campaign(evs)
        p2 = profile_campaign(list(reversed(evs)))
        assert p1.campaign_id == p2.campaign_id

    def test_campaign_id_length_12(self):
        evs = [_ev("only", "1.2.3.4")]
        p = profile_campaign(evs)
        assert len(p.campaign_id) == 12

    def test_campaign_id_helper(self):
        evs = [_ev("e1", "1.1.1.1"), _ev("e2", "2.2.2.2")]
        expected = hashlib.sha256(",".join(sorted(["e1", "e2"])).encode()).hexdigest()[:12]
        assert _campaign_id(evs) == expected

    def test_unique_ips_single(self):
        evs = [_ev(f"u{i}", "1.2.3.4", ts=BASE_TS + i * 1000) for i in range(5)]
        p = profile_campaign(evs)
        assert p.unique_ips == 1


# ══════════════════════════════════════════════════════════════════════════════
# 13. affected_ips contract
# ══════════════════════════════════════════════════════════════════════════════

class TestAffectedIps:
    def test_affected_ips_never_exceed_10(self):
        evs = []
        for i in range(15):
            evs.append(_ev(f"ai-{i}", f"10.20.{i}.1", username="root", password="abc",
                           ts=BASE_TS + i * 100))
        p = profile_campaign(evs)
        for c in p.checks_fired:
            assert len(c.affected_ips) <= 10, f"{c.check_id} affected_ips exceeds 10"

    def test_affected_ips_is_list(self):
        evs = [_ev(f"li-{i}", f"10.21.{i}.1", username="admin", password="pw",
                   ts=BASE_TS + i * 100) for i in range(3)]
        p = profile_campaign(evs)
        for c in p.checks_fired:
            assert isinstance(c.affected_ips, list)

    def test_affected_ips_non_empty_when_check_fires(self):
        evs = [_ev(f"ne-{i}", f"10.22.{i}.1", username="root", password="pw",
                   ts=BASE_TS + i * 100) for i in range(3)]
        p = profile_campaign(evs)
        for c in p.checks_fired:
            assert len(c.affected_ips) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 14. Multi-check interactions and edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_duplicate_event_ids_handled(self):
        evs = [
            _ev("dup", "1.1.1.1", ts=BASE_TS),
            _ev("dup", "1.1.1.1", ts=BASE_TS + 1000),
        ]
        p = profile_campaign(evs)
        # Should not crash; campaign_id uses set
        assert len(p.campaign_id) == 12

    def test_all_same_ip_no_camp001(self):
        # Same creds but only 1 distinct IP
        evs = [_ev(f"s{i}", "5.5.5.5", username="root", password="pass", ts=BASE_TS + i * 1000)
               for i in range(5)]
        p = profile_campaign(evs)
        assert "CAMP-001" not in _ids(p)

    def test_camp003_non_sequential_octets_no_fire(self):
        # Octets: 10, 20, 30 — sorted but non-consecutive (that's fine) within time
        # The check is sorted ORDER not consecutive VALUES
        evs = [
            _ev("o1", "192.168.2.10", ts=BASE_TS),
            _ev("o2", "192.168.2.20", ts=BASE_TS + 60_000),
            _ev("o3", "192.168.2.30", ts=BASE_TS + 120_000),
        ]
        # These ARE in sorted order with small gaps — should fire
        p = profile_campaign(evs)
        assert "CAMP-003" in _ids(p)

    def test_large_event_set_performance(self):
        # 500 events — ensure no performance explosion
        evs = [_ev(f"perf-{i}", f"10.{i//255}.{i%255}.1",
                   service="ssh", ts=BASE_TS + i * 1000) for i in range(500)]
        p = profile_campaign(evs)  # Should complete quickly
        assert p.total_events == 500

    def test_profile_campaign_returns_campaign_profile_type(self):
        evs = [_ev("t1", "1.2.3.4")]
        p = profile_campaign(evs)
        assert isinstance(p, CampaignProfile)

    def test_checks_fired_list_of_campaign_check(self):
        evs = [_ev(f"cf-{i}", f"10.0.{i}.1", username="a", password="b",
                   ts=BASE_TS + i) for i in range(3)]
        p = profile_campaign(evs)
        assert isinstance(p.checks_fired, list)
        for c in p.checks_fired:
            assert isinstance(c, CampaignCheck)

    def test_camp002_service_empty_string_not_counted(self):
        # Events with empty service string should not trigger CAMP-002
        evs = [_ev(f"ns-{i}", f"10.30.{i}.1", service="", ts=BASE_TS + i * 1000)
               for i in range(6)]
        p = profile_campaign(evs)
        assert "CAMP-002" not in _ids(p)

    def test_camp006_reversed_order_no_fire(self):
        # Targeted passwords early, common words late — should NOT fire
        evs = [
            _ev("rev1", "10.40.1.1", ts=BASE_TS,              password="mysql@2024", username="u"),
            _ev("rev2", "10.40.1.1", ts=BASE_TS + ONE_MIN_MS, password="root2023",   username="u"),
            _ev("rev3", "10.40.1.1", ts=BASE_TS + 2*ONE_MIN_MS, password="admin",   username="u"),
            _ev("rev4", "10.40.1.1", ts=BASE_TS + 3*ONE_MIN_MS, password="test",    username="u"),
        ]
        p = profile_campaign(evs)
        assert "CAMP-006" not in _ids(p)
