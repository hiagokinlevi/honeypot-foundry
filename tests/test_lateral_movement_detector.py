# test_lateral_movement_detector.py
# Part of Cyber Port — Honeypot Foundry
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0) — https://creativecommons.org/licenses/by/4.0/
#
# Full test suite for lateral_movement_detector.py
# Run with: python3 -m pytest tests/test_lateral_movement_detector.py -q

import sys
import os

# Allow importing the analysis package without installing it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.lateral_movement_detector import (
    HoneypotEvent,
    LATMFinding,
    LATMResult,
    _CHECK_WEIGHTS,
    _SEVERITY,
    _is_internal_ip,
    _events_in_window,
    _compute_risk,
    _threat_level,
    analyze,
    analyze_stream,
)

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

BASE_TS = 1_000_000  # arbitrary base timestamp in milliseconds
SEC = 1_000          # 1 second in ms
MIN = 60 * SEC       # 1 minute in ms
HOUR = 60 * MIN      # 1 hour in ms


def _ev(
    event_id: str,
    source_ip: str = "1.2.3.4",
    honeypot_host: str = "hp-ssh-01",
    username: str = "admin",
    password: str = "pass",
    success: bool = False,
    timestamp_ms: int = BASE_TS,
) -> HoneypotEvent:
    """Factory function for creating test events with sane defaults."""
    return HoneypotEvent(
        event_id=event_id,
        source_ip=source_ip,
        honeypot_host=honeypot_host,
        username=username,
        password=password,
        success=success,
        timestamp_ms=timestamp_ms,
    )


def _find_ids(result: LATMResult) -> set:
    """Return the set of check_ids present in result.findings."""
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# Tests for _is_internal_ip
# ---------------------------------------------------------------------------

class TestIsInternalIp:
    def test_class_a_private(self):
        assert _is_internal_ip("10.0.0.1") is True

    def test_class_a_private_boundary_low(self):
        assert _is_internal_ip("10.0.0.0") is True

    def test_class_a_private_boundary_high(self):
        assert _is_internal_ip("10.255.255.255") is True

    def test_class_b_private_172_16(self):
        assert _is_internal_ip("172.16.0.1") is True

    def test_class_b_private_172_31(self):
        assert _is_internal_ip("172.31.255.255") is True

    def test_class_b_NOT_private_172_15(self):
        # 172.15.x is NOT in RFC1918
        assert _is_internal_ip("172.15.0.1") is False

    def test_class_b_NOT_private_172_32(self):
        # 172.32.x is NOT in RFC1918
        assert _is_internal_ip("172.32.0.1") is False

    def test_class_c_private(self):
        assert _is_internal_ip("192.168.1.1") is True

    def test_class_c_private_boundary(self):
        assert _is_internal_ip("192.168.0.0") is True

    def test_loopback(self):
        assert _is_internal_ip("127.0.0.1") is True

    def test_loopback_other(self):
        assert _is_internal_ip("127.255.255.255") is True

    def test_public_ip(self):
        assert _is_internal_ip("8.8.8.8") is False

    def test_public_ip_2(self):
        assert _is_internal_ip("203.0.113.5") is False

    def test_malformed_ip(self):
        assert _is_internal_ip("not.an.ip") is False

    def test_empty_string(self):
        assert _is_internal_ip("") is False


# ---------------------------------------------------------------------------
# Tests for _events_in_window
# ---------------------------------------------------------------------------

class TestEventsInWindow:
    def test_empty_list_returns_false(self):
        assert _events_in_window([], 60_000) is False

    def test_single_event_returns_false(self):
        evs = [_ev("e1", timestamp_ms=BASE_TS)]
        assert _events_in_window(evs, 60_000) is False

    def test_two_events_inside_window(self):
        evs = [
            _ev("e1", timestamp_ms=BASE_TS),
            _ev("e2", timestamp_ms=BASE_TS + 30_000),
        ]
        assert _events_in_window(evs, 60_000) is True

    def test_two_events_outside_window(self):
        evs = [
            _ev("e1", timestamp_ms=BASE_TS),
            _ev("e2", timestamp_ms=BASE_TS + 70_000),
        ]
        assert _events_in_window(evs, 60_000) is False

    def test_two_events_exactly_at_window_boundary(self):
        # window_ms = 60_000; difference = 60_000 means ts_right - ts_left == window_ms
        # The condition is > window_ms, so exactly at boundary is inside
        evs = [
            _ev("e1", timestamp_ms=BASE_TS),
            _ev("e2", timestamp_ms=BASE_TS + 60_000),
        ]
        assert _events_in_window(evs, 60_000) is True

    def test_unsorted_events_handled(self):
        evs = [
            _ev("e2", timestamp_ms=BASE_TS + 30_000),
            _ev("e1", timestamp_ms=BASE_TS),
        ]
        assert _events_in_window(evs, 60_000) is True


# ---------------------------------------------------------------------------
# Tests for _compute_risk and _threat_level
# ---------------------------------------------------------------------------

class TestRiskHelpers:
    def test_single_check(self):
        assert _compute_risk(["LATM-001"]) == 45

    def test_duplicate_check_ids_counted_once(self):
        assert _compute_risk(["LATM-001", "LATM-001"]) == 45

    def test_two_distinct_checks(self):
        # LATM-001=45 + LATM-002=25 = 70
        assert _compute_risk(["LATM-001", "LATM-002"]) == 70

    def test_cap_at_100(self):
        # All checks together: 45+25+20+25+25+15+20 = 175 -> capped at 100
        assert _compute_risk(list(_CHECK_WEIGHTS.keys())) == 100

    def test_empty_list_returns_zero(self):
        assert _compute_risk([]) == 0

    def test_threat_level_critical(self):
        assert _threat_level(70) == "CRITICAL"

    def test_threat_level_critical_above(self):
        assert _threat_level(100) == "CRITICAL"

    def test_threat_level_high(self):
        assert _threat_level(40) == "HIGH"

    def test_threat_level_high_just_below_critical(self):
        assert _threat_level(69) == "HIGH"

    def test_threat_level_medium(self):
        assert _threat_level(15) == "MEDIUM"

    def test_threat_level_medium_just_below_high(self):
        assert _threat_level(39) == "MEDIUM"

    def test_threat_level_low(self):
        assert _threat_level(0) == "LOW"

    def test_threat_level_low_just_below_medium(self):
        assert _threat_level(14) == "LOW"


# ---------------------------------------------------------------------------
# Tests for LATM-001 — credential reuse across source IPs
# ---------------------------------------------------------------------------

class TestLATM001:
    def test_fires_when_same_cred_two_ips_within_hour(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="admin", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="admin", password="p", timestamp_ms=BASE_TS + 30 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" in _find_ids(result)

    def test_does_not_fire_when_same_cred_same_ip(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="admin", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", username="admin", password="p", timestamp_ms=BASE_TS + 30 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_does_not_fire_when_same_ip_but_different_password(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="admin", password="p1", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="admin", password="p2", timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_does_not_fire_when_creds_outside_1_hour_window(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 61 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_does_not_fire_when_username_is_none(self):
        events = [
            HoneypotEvent("e1", "1.1.1.1", "hp-ssh-01", None, "p", False, BASE_TS),
            HoneypotEvent("e2", "2.2.2.2", "hp-ssh-01", None, "p", False, BASE_TS + MIN),
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_does_not_fire_when_password_is_none(self):
        events = [
            HoneypotEvent("e1", "1.1.1.1", "hp-ssh-01", "admin", None, False, BASE_TS),
            HoneypotEvent("e2", "2.2.2.2", "hp-ssh-01", "admin", None, False, BASE_TS + MIN),
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_finding_masks_password(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="secret", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="secret", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-001")
        assert "secret" not in finding.detail
        assert "****" in finding.detail

    def test_finding_severity_is_critical(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-001")
        assert finding.severity == "CRITICAL"

    def test_finding_weight(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-001")
        assert finding.weight == 45

    def test_source_ips_included_in_finding(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-001")
        assert "1.1.1.1" in finding.source_ips
        assert "2.2.2.2" in finding.source_ips

    def test_three_ips_same_credential(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 10 * MIN),
            _ev("e3", source_ip="3.3.3.3", username="u", password="p", timestamp_ms=BASE_TS + 20 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" in _find_ids(result)

    def test_at_exactly_60_min_boundary(self):
        # difference == 60 * MIN == 3_600_000 ms, condition is >, so this IS inside window
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 60 * MIN),
        ]
        result = analyze(events)
        assert "LATM-001" in _find_ids(result)


# ---------------------------------------------------------------------------
# Tests for LATM-002 — sequential honeypot host access
# ---------------------------------------------------------------------------

class TestLATM002:
    def test_fires_when_three_hosts_within_30_min(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", timestamp_ms=BASE_TS + 5 * MIN),
            _ev("e3", source_ip="1.1.1.1", honeypot_host="hp-ftp-01", timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        assert "LATM-002" in _find_ids(result)

    def test_does_not_fire_with_exactly_two_hosts(self):
        # >2 means 3 or more; exactly 2 is fine
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        assert "LATM-002" not in _find_ids(result)

    def test_does_not_fire_with_single_host_many_events(self):
        events = [
            _ev(f"e{i}", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", timestamp_ms=BASE_TS + i * MIN)
            for i in range(10)
        ]
        result = analyze(events)
        assert "LATM-002" not in _find_ids(result)

    def test_does_not_fire_when_hosts_outside_30_min_window(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", timestamp_ms=BASE_TS + 16 * MIN),
            _ev("e3", source_ip="1.1.1.1", honeypot_host="hp-ftp-01", timestamp_ms=BASE_TS + 32 * MIN),
        ]
        result = analyze(events)
        assert "LATM-002" not in _find_ids(result)

    def test_different_ips_not_aggregated(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", honeypot_host="hp-http-01", timestamp_ms=BASE_TS + 5 * MIN),
            _ev("e3", source_ip="3.3.3.3", honeypot_host="hp-ftp-01", timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        assert "LATM-002" not in _find_ids(result)

    def test_finding_contains_correct_ip(self):
        events = [
            _ev("e1", source_ip="5.5.5.5", honeypot_host="hp-A", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="5.5.5.5", honeypot_host="hp-B", timestamp_ms=BASE_TS + 5 * MIN),
            _ev("e3", source_ip="5.5.5.5", honeypot_host="hp-C", timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-002")
        assert finding.source_ips == ["5.5.5.5"]

    def test_weight_is_25(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-A", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-B", timestamp_ms=BASE_TS + 5 * MIN),
            _ev("e3", source_ip="1.1.1.1", honeypot_host="hp-C", timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-002")
        assert finding.weight == 25


# ---------------------------------------------------------------------------
# Tests for LATM-003 — username enumeration
# ---------------------------------------------------------------------------

class TestLATM003:
    def _enum_events(self, usernames, ip="1.1.1.1", base=BASE_TS, gap=MIN):
        """Create events with different usernames spaced gap ms apart."""
        return [
            HoneypotEvent(
                f"e{i}", ip, "hp-ssh-01", u, "pass", False, base + i * gap
            )
            for i, u in enumerate(usernames)
        ]

    def test_fires_with_six_distinct_usernames_within_10_min(self):
        usernames = ["u1", "u2", "u3", "u4", "u5", "u6"]
        events = self._enum_events(usernames, gap=MIN)
        result = analyze(events)
        assert "LATM-003" in _find_ids(result)

    def test_does_not_fire_with_exactly_five_usernames(self):
        usernames = ["u1", "u2", "u3", "u4", "u5"]
        events = self._enum_events(usernames, gap=MIN)
        result = analyze(events)
        assert "LATM-003" not in _find_ids(result)

    def test_does_not_fire_when_outside_10_min_window(self):
        # Six usernames spread so that no 6 fit inside a 10-minute window.
        # With gap = 3*MIN, span for 6 events = 5 * 3*MIN = 15*MIN > 10*MIN.
        # The best any sub-window of 6 consecutive events can do is also 15 min,
        # but a window of 5 events spans 12 min which is still > 10 min.
        # Only 4 consecutive events fit inside 10 min (span = 3*3*MIN = 9*MIN).
        usernames = ["u1", "u2", "u3", "u4", "u5", "u6"]
        events = self._enum_events(usernames, gap=3 * MIN)
        result = analyze(events)
        assert "LATM-003" not in _find_ids(result)

    def test_does_not_count_none_usernames(self):
        # 5 named + 2 None — should not fire
        events = [
            HoneypotEvent(f"e{i}", "1.1.1.1", "hp-ssh-01", f"u{i}", "p", False, BASE_TS + i * MIN)
            for i in range(5)
        ] + [
            HoneypotEvent("e5", "1.1.1.1", "hp-ssh-01", None, "p", False, BASE_TS + 5 * MIN),
            HoneypotEvent("e6", "1.1.1.1", "hp-ssh-01", None, "p", False, BASE_TS + 6 * MIN),
        ]
        result = analyze(events)
        assert "LATM-003" not in _find_ids(result)

    def test_finding_lists_usernames_in_detail(self):
        usernames = ["alice", "bob", "carol", "dave", "eve", "frank"]
        events = self._enum_events(usernames, gap=MIN)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-003")
        for u in usernames:
            assert u in finding.detail

    def test_weight_is_20(self):
        usernames = ["u1", "u2", "u3", "u4", "u5", "u6"]
        events = self._enum_events(usernames, gap=MIN)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-003")
        assert finding.weight == 20

    def test_severity_is_high(self):
        usernames = ["u1", "u2", "u3", "u4", "u5", "u6"]
        events = self._enum_events(usernames, gap=MIN)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-003")
        assert finding.severity == "HIGH"

    def test_repeated_username_not_counted_twice(self):
        # u1 repeated — only 5 distinct usernames
        events = self._enum_events(["u1", "u1", "u2", "u3", "u4", "u5"], gap=MIN)
        result = analyze(events)
        assert "LATM-003" not in _find_ids(result)


# ---------------------------------------------------------------------------
# Tests for LATM-004 — internal IP detection
# ---------------------------------------------------------------------------

class TestLATM004:
    def test_fires_for_class_a_ip(self):
        events = [_ev("e1", source_ip="10.0.0.5")]
        result = analyze(events)
        assert "LATM-004" in _find_ids(result)

    def test_fires_for_class_c_ip(self):
        events = [_ev("e1", source_ip="192.168.1.100")]
        result = analyze(events)
        assert "LATM-004" in _find_ids(result)

    def test_fires_for_class_b_ip(self):
        events = [_ev("e1", source_ip="172.16.0.1")]
        result = analyze(events)
        assert "LATM-004" in _find_ids(result)

    def test_fires_for_loopback(self):
        events = [_ev("e1", source_ip="127.0.0.1")]
        result = analyze(events)
        assert "LATM-004" in _find_ids(result)

    def test_does_not_fire_for_external_ip(self):
        events = [_ev("e1", source_ip="8.8.8.8")]
        result = analyze(events)
        assert "LATM-004" not in _find_ids(result)

    def test_one_finding_for_multiple_internal_ips(self):
        events = [
            _ev("e1", source_ip="10.0.0.1"),
            _ev("e2", source_ip="192.168.1.1"),
        ]
        result = analyze(events)
        latm004_findings = [f for f in result.findings if f.check_id == "LATM-004"]
        assert len(latm004_findings) == 1

    def test_finding_lists_all_internal_ips(self):
        events = [
            _ev("e1", source_ip="10.0.0.1"),
            _ev("e2", source_ip="192.168.5.5"),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-004")
        assert "10.0.0.1" in finding.source_ips
        assert "192.168.5.5" in finding.source_ips

    def test_external_ips_not_in_finding(self):
        events = [
            _ev("e1", source_ip="10.0.0.1"),
            _ev("e2", source_ip="8.8.8.8"),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-004")
        assert "8.8.8.8" not in finding.source_ips

    def test_weight_is_25(self):
        events = [_ev("e1", source_ip="10.1.2.3")]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-004")
        assert finding.weight == 25

    def test_event_ids_included(self):
        events = [_ev("evt-internal", source_ip="192.168.0.1")]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-004")
        assert "evt-internal" in finding.event_ids


# ---------------------------------------------------------------------------
# Tests for LATM-005 — post-authentication lateral pivot
# ---------------------------------------------------------------------------

class TestLATM005:
    def test_fires_when_success_then_different_host_within_5_min(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", success=False, timestamp_ms=BASE_TS + 4 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" in _find_ids(result)

    def test_does_not_fire_when_follow_up_same_host(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=False, timestamp_ms=BASE_TS + 2 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" not in _find_ids(result)

    def test_does_not_fire_when_no_success(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=False, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", success=False, timestamp_ms=BASE_TS + 4 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" not in _find_ids(result)

    def test_does_not_fire_when_follow_up_outside_5_min(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", success=False, timestamp_ms=BASE_TS + 6 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" not in _find_ids(result)

    def test_fires_for_both_follow_up_success_and_fail(self):
        # Follow-up event can be success or fail — only need different host
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", success=True, timestamp_ms=BASE_TS + 2 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" in _find_ids(result)

    def test_finding_contains_both_hosts(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-ssh-01", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-http-01", success=False, timestamp_ms=BASE_TS + 3 * MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-005")
        assert "hp-ssh-01" in finding.detail
        assert "hp-http-01" in finding.detail

    def test_weight_is_25(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-A", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-B", success=False, timestamp_ms=BASE_TS + MIN),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-005")
        assert finding.weight == 25

    def test_at_exactly_5_min_boundary(self):
        # difference == 5*MIN, condition is >, so exactly 5 min IS within window
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-A", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-B", success=False, timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        assert "LATM-005" in _find_ids(result)


# ---------------------------------------------------------------------------
# Tests for LATM-006 — post-compromise reconnaissance
# ---------------------------------------------------------------------------

class TestLATM006:
    def test_fires_when_fail_after_success(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        assert "LATM-006" in _find_ids(result)

    def test_does_not_fire_when_only_failures(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        assert "LATM-006" not in _find_ids(result)

    def test_does_not_fire_when_only_successes(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        assert "LATM-006" not in _find_ids(result)

    def test_does_not_fire_when_fail_before_success(self):
        # Fail comes before the success — not a post-compromise scenario
        events = [
            _ev("e1", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        assert "LATM-006" not in _find_ids(result)

    def test_fires_within_24_hours(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + 23 * HOUR),
        ]
        result = analyze(events)
        assert "LATM-006" in _find_ids(result)

    def test_firing_includes_success_event_id(self):
        events = [
            _ev("success-evt", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("fail-evt", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-006")
        assert "success-evt" in finding.event_ids
        assert "fail-evt" in finding.event_ids

    def test_weight_is_15(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-006")
        assert finding.weight == 15

    def test_severity_is_medium(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-006")
        assert finding.severity == "MEDIUM"

    def test_multiple_failures_after_success_all_included(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + HOUR),
            _ev("e3", source_ip="1.1.1.1", success=False, timestamp_ms=BASE_TS + 2 * HOUR),
        ]
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-006")
        assert "e2" in finding.event_ids
        assert "e3" in finding.event_ids


# ---------------------------------------------------------------------------
# Tests for LATM-007 — burst activity / automation
# ---------------------------------------------------------------------------

class TestLATM007:
    def _burst(self, count, ip="1.1.1.1", gap=SEC):
        """Create *count* events spaced *gap* ms apart from the same IP."""
        return [
            _ev(f"e{i}", source_ip=ip, timestamp_ms=BASE_TS + i * gap)
            for i in range(count)
        ]

    def test_fires_with_11_events_in_one_minute(self):
        events = self._burst(11, gap=5 * SEC)
        result = analyze(events)
        assert "LATM-007" in _find_ids(result)

    def test_does_not_fire_with_exactly_10_events_in_one_minute(self):
        events = self._burst(10, gap=5 * SEC)
        result = analyze(events)
        assert "LATM-007" not in _find_ids(result)

    def test_does_not_fire_when_spread_over_more_than_a_minute(self):
        # 11 events but each 7 seconds apart = 70 seconds total > 1 minute
        events = self._burst(11, gap=7 * SEC)
        result = analyze(events)
        assert "LATM-007" not in _find_ids(result)

    def test_different_ips_not_aggregated(self):
        # 6 events from each IP — individually below threshold
        events = self._burst(6, ip="1.1.1.1", gap=5 * SEC) + self._burst(6, ip="2.2.2.2", gap=5 * SEC)
        result = analyze(events)
        assert "LATM-007" not in _find_ids(result)

    def test_finding_source_ip_is_correct(self):
        events = self._burst(12, ip="9.9.9.9", gap=3 * SEC)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-007")
        assert finding.source_ips == ["9.9.9.9"]

    def test_weight_is_20(self):
        events = self._burst(11, gap=5 * SEC)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-007")
        assert finding.weight == 20

    def test_severity_is_high(self):
        events = self._burst(11, gap=5 * SEC)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-007")
        assert finding.severity == "HIGH"

    def test_event_ids_all_in_burst_window(self):
        events = self._burst(11, gap=5 * SEC)
        result = analyze(events)
        finding = next(f for f in result.findings if f.check_id == "LATM-007")
        # All 11 event IDs should be captured
        assert len(finding.event_ids) == 11

    def test_large_burst_fires(self):
        events = self._burst(100, gap=500)  # 100 events 500ms apart = 50 sec window
        result = analyze(events)
        assert "LATM-007" in _find_ids(result)


# ---------------------------------------------------------------------------
# Tests for LATMResult methods
# ---------------------------------------------------------------------------

class TestLATMResult:
    def _simple_result(self) -> LATMResult:
        """Return a result with one CRITICAL finding."""
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        return analyze(events)

    def test_to_dict_has_risk_score(self):
        result = self._simple_result()
        d = result.to_dict()
        assert "risk_score" in d

    def test_to_dict_has_threat_level(self):
        result = self._simple_result()
        d = result.to_dict()
        assert "threat_level" in d

    def test_to_dict_has_findings_list(self):
        result = self._simple_result()
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_has_required_keys(self):
        result = self._simple_result()
        d = result.to_dict()
        f = d["findings"][0]
        for key in ("check_id", "severity", "title", "detail", "weight", "source_ips", "event_ids"):
            assert key in f

    def test_summary_contains_threat_level(self):
        result = self._simple_result()
        s = result.summary()
        assert result.threat_level in s

    def test_summary_contains_risk_score(self):
        result = self._simple_result()
        s = result.summary()
        assert str(result.risk_score) in s

    def test_by_severity_groups_correctly(self):
        result = self._simple_result()
        grouped = result.by_severity()
        # LATM-001 is CRITICAL
        assert "CRITICAL" in grouped

    def test_empty_events_result(self):
        result = analyze([])
        assert result.findings == []
        assert result.risk_score == 0
        assert result.threat_level == "LOW"

    def test_risk_score_does_not_exceed_100(self):
        # Fire all checks to verify cap
        # LATM-001: same cred different IPs
        # LATM-002: same IP >2 hosts in 30 min
        # LATM-003: >5 usernames in 10 min
        # LATM-004: internal IP
        # LATM-005: success then different host within 5 min
        # LATM-006: fail after success
        # LATM-007: burst >10 in 1 min
        events = []
        # LATM-001 trigger
        events.append(_ev("c1", source_ip="10.0.0.1", username="u", password="p", timestamp_ms=BASE_TS))
        events.append(_ev("c2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + MIN))
        # LATM-002 and LATM-007 trigger from same IP (burst + many hosts)
        for i in range(11):
            events.append(
                HoneypotEvent(
                    f"b{i}", "3.3.3.3", f"hp-{i:02d}", "admin", "x", False,
                    BASE_TS + i * (4 * SEC)
                )
            )
        # LATM-003 trigger
        for i in range(6):
            events.append(
                HoneypotEvent(f"u{i}", "4.4.4.4", "hp-ssh-01", f"user{i}", "pw", False, BASE_TS + i * MIN)
            )
        # LATM-004 already triggered by 10.0.0.1 above
        # LATM-005 trigger
        events.append(_ev("s1", source_ip="5.5.5.5", honeypot_host="hp-A", success=True, timestamp_ms=BASE_TS))
        events.append(_ev("s2", source_ip="5.5.5.5", honeypot_host="hp-B", success=False, timestamp_ms=BASE_TS + 2 * MIN))
        # LATM-006 trigger
        events.append(_ev("r1", source_ip="6.6.6.6", success=True, timestamp_ms=BASE_TS))
        events.append(_ev("r2", source_ip="6.6.6.6", success=False, timestamp_ms=BASE_TS + HOUR))

        result = analyze(events)
        assert result.risk_score <= 100


# ---------------------------------------------------------------------------
# Tests for analyze_stream
# ---------------------------------------------------------------------------

class TestAnalyzeStream:
    def test_empty_events_returns_empty_list(self):
        assert analyze_stream([]) == []

    def test_single_window(self):
        events = [_ev(f"e{i}") for i in range(5)]
        results = analyze_stream(events, window_size=10)
        assert len(results) == 1

    def test_two_full_windows(self):
        events = [_ev(f"e{i}") for i in range(20)]
        results = analyze_stream(events, window_size=10)
        assert len(results) == 2

    def test_partial_last_window(self):
        events = [_ev(f"e{i}") for i in range(15)]
        results = analyze_stream(events, window_size=10)
        assert len(results) == 2

    def test_each_result_is_latm_result(self):
        events = [_ev(f"e{i}") for i in range(5)]
        results = analyze_stream(events, window_size=5)
        assert all(isinstance(r, LATMResult) for r in results)

    def test_window_size_1000_default(self):
        events = [_ev(f"e{i}") for i in range(500)]
        results = analyze_stream(events)
        assert len(results) == 1

    def test_window_size_zero_returns_empty(self):
        events = [_ev(f"e{i}") for i in range(5)]
        results = analyze_stream(events, window_size=0)
        assert results == []

    def test_detection_within_window(self):
        # Put a LATM-004 event in the second window only
        events = [_ev(f"e{i}", source_ip="8.8.8.8") for i in range(10)]
        events += [_ev("internal", source_ip="192.168.0.1")]
        results = analyze_stream(events, window_size=10)
        # First window (external only) should not have LATM-004
        assert "LATM-004" not in _find_ids(results[0])
        # Second window should have LATM-004
        assert "LATM-004" in _find_ids(results[1])


# ---------------------------------------------------------------------------
# Integration / combined scenario tests
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_no_events_produces_low_threat(self):
        result = analyze([])
        assert result.threat_level == "LOW"
        assert result.risk_score == 0

    def test_single_event_produces_no_critical_findings(self):
        events = [_ev("solo")]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)
        assert "LATM-002" not in _find_ids(result)
        assert "LATM-003" not in _find_ids(result)
        assert "LATM-005" not in _find_ids(result)
        assert "LATM-006" not in _find_ids(result)
        assert "LATM-007" not in _find_ids(result)

    def test_all_external_ips_no_latm004(self):
        events = [_ev(f"e{i}", source_ip=f"8.8.{i}.{i}") for i in range(5)]
        result = analyze(events)
        assert "LATM-004" not in _find_ids(result)

    def test_multiple_checks_can_fire_simultaneously(self):
        # Craft events that trigger LATM-001, LATM-004 together
        events = [
            _ev("e1", source_ip="10.0.0.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        fired = _find_ids(result)
        assert "LATM-001" in fired
        assert "LATM-004" in fired

    def test_risk_score_reflects_multiple_checks(self):
        # LATM-001 (45) + LATM-004 (25) = 70 -> CRITICAL
        events = [
            _ev("e1", source_ip="10.0.0.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        assert result.risk_score == 70
        assert result.threat_level == "CRITICAL"

    def test_unique_credential_same_ip_does_not_pollute(self):
        # Lots of different credentials from same IP — no LATM-001
        events = [
            _ev(f"e{i}", source_ip="1.1.1.1", username=f"u{i}", password=f"p{i}", timestamp_ms=BASE_TS + i * MIN)
            for i in range(10)
        ]
        result = analyze(events)
        assert "LATM-001" not in _find_ids(result)

    def test_check_weights_dict_complete(self):
        for check_id in ("LATM-001", "LATM-002", "LATM-003", "LATM-004", "LATM-005", "LATM-006", "LATM-007"):
            assert check_id in _CHECK_WEIGHTS
            assert isinstance(_CHECK_WEIGHTS[check_id], int)
            assert _CHECK_WEIGHTS[check_id] > 0

    def test_severity_dict_complete(self):
        for check_id in ("LATM-001", "LATM-002", "LATM-003", "LATM-004", "LATM-005", "LATM-006", "LATM-007"):
            assert check_id in _SEVERITY
            assert _SEVERITY[check_id] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_finding_event_ids_are_strings(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", username="u", password="p", timestamp_ms=BASE_TS),
            _ev("e2", source_ip="2.2.2.2", username="u", password="p", timestamp_ms=BASE_TS + 5 * MIN),
        ]
        result = analyze(events)
        for finding in result.findings:
            assert all(isinstance(eid, str) for eid in finding.event_ids)

    def test_finding_source_ips_are_strings(self):
        events = [_ev("e1", source_ip="10.0.0.1")]
        result = analyze(events)
        for finding in result.findings:
            assert all(isinstance(ip, str) for ip in finding.source_ips)

    def test_high_volume_events_no_crash(self):
        events = [
            _ev(f"ev{i}", source_ip="1.2.3.4", timestamp_ms=BASE_TS + i * 100)
            for i in range(500)
        ]
        result = analyze(events)
        assert isinstance(result, LATMResult)

    def test_latm005_not_fire_when_no_events_after_success(self):
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-A", success=True, timestamp_ms=BASE_TS),
        ]
        result = analyze(events)
        assert "LATM-005" not in _find_ids(result)

    def test_threat_level_high_at_score_40(self):
        # Construct a result manually to test boundary
        result = LATMResult(findings=[], risk_score=40, threat_level="HIGH")
        assert result.threat_level == "HIGH"

    def test_threat_level_medium_at_score_15(self):
        result = LATMResult(findings=[], risk_score=15, threat_level="MEDIUM")
        assert result.threat_level == "MEDIUM"

    def test_latm002_fires_with_success_events(self):
        # LATM-002 counts both successes and failures
        events = [
            _ev("e1", source_ip="1.1.1.1", honeypot_host="hp-A", success=True, timestamp_ms=BASE_TS),
            _ev("e2", source_ip="1.1.1.1", honeypot_host="hp-B", success=False, timestamp_ms=BASE_TS + 5 * MIN),
            _ev("e3", source_ip="1.1.1.1", honeypot_host="hp-C", success=True, timestamp_ms=BASE_TS + 10 * MIN),
        ]
        result = analyze(events)
        assert "LATM-002" in _find_ids(result)

    def test_latm003_window_exactly_10_min_fires(self):
        # 6 events exactly at 10-min boundary — difference = 10*MIN which is not > 10*MIN
        events = [
            HoneypotEvent(f"e{i}", "1.1.1.1", "hp-ssh-01", f"u{i}", "p", False, BASE_TS + i * (2 * MIN))
            for i in range(6)
        ]
        # Span = 5 * 2*MIN = 10*MIN; condition is > 10*MIN, so exactly 10*MIN is inside
        result = analyze(events)
        assert "LATM-003" in _find_ids(result)

    def test_latm007_exactly_at_1_min_boundary(self):
        # 11 events exactly spanning 60 seconds — not > 60s, so inside window
        events = [
            _ev(f"e{i}", timestamp_ms=BASE_TS + i * (6 * SEC))
            for i in range(11)
        ]
        # Span = 10 * 6 * SEC = 60 * SEC = 60_000 ms; condition is > 60_000, so 60_000 is inside
        result = analyze(events)
        assert "LATM-007" in _find_ids(result)
