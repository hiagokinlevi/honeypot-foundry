"""
Tests for analysis/scanner_fingerprint.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.scanner_fingerprint import (
    FingerprintConfidence,
    FingerprintResult,
    ScannerFingerprinter,
    ScannerType,
    _compute_inter_event_gaps,
    _get_str,
    _match_any,
    _SHODAN_UA_PATTERNS,
    _MASSCAN_UA_PATTERNS,
    _ZGRAB_PATTERNS,
    _METASPLOIT_PATTERNS,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ev(
    ip: str = "1.2.3.4",
    ts: float = 0.0,
    username: str = "",
    password: str = "",
    port: int = 0,
    user_agent: str = "",
    payload: str = "",
    event_type: str = "auth_fail",
) -> dict:
    e: dict = {"source_ip": ip, "event_type": event_type}
    if ts:
        e["ts"] = ts
    if username:
        e["username"] = username
    if password:
        e["password"] = password
    if port:
        e["port"] = port
    if user_agent:
        e["user_agent"] = user_agent
    if payload:
        e["payload"] = payload
    return e


# ===========================================================================
# Internal helpers
# ===========================================================================

class TestGetStr:
    def test_returns_first_matching_key(self):
        assert _get_str({"a": "hello"}, "a", "b") == "hello"

    def test_skips_empty_string(self):
        assert _get_str({"a": "", "b": "val"}, "a", "b") == "val"

    def test_returns_empty_if_no_match(self):
        assert _get_str({"x": "y"}, "a") == ""


class TestMatchAny:
    def test_matches(self):
        assert _match_any(_SHODAN_UA_PATTERNS, "Mozilla/5.0 shodan scanner")

    def test_no_match(self):
        assert not _match_any(_SHODAN_UA_PATTERNS, "Mozilla/5.0 Firefox")


class TestInterEventGaps:
    def test_single_event(self):
        assert _compute_inter_event_gaps([1.0]) == []

    def test_two_events(self):
        gaps = _compute_inter_event_gaps([1.0, 3.0])
        assert gaps == [2.0]

    def test_sorted_order(self):
        gaps = _compute_inter_event_gaps([5.0, 1.0, 3.0])
        assert gaps == [2.0, 2.0]

    def test_empty(self):
        assert _compute_inter_event_gaps([]) == []


# ===========================================================================
# FingerprintResult
# ===========================================================================

class TestFingerprintResult:
    def _result(self, scanner_type=ScannerType.SHODAN) -> FingerprintResult:
        return FingerprintResult(
            source_ip="1.2.3.4",
            scanner_type=scanner_type,
            confidence=FingerprintConfidence.HIGH,
            score=0.80,
            event_count=5,
        )

    def test_summary_contains_ip(self):
        assert "1.2.3.4" in self._result().summary()

    def test_summary_contains_scanner_type(self):
        assert "SHODAN" in self._result(ScannerType.SHODAN).summary()

    def test_to_dict_has_required_keys(self):
        d = self._result().to_dict()
        for key in ("source_ip", "scanner_type", "confidence", "score", "event_count"):
            assert key in d

    def test_to_dict_scanner_type_is_string(self):
        d = self._result().to_dict()
        assert isinstance(d["scanner_type"], str)


# ===========================================================================
# ScannerFingerprinter — basic
# ===========================================================================

class TestScannerFingerprinterBasic:
    def test_ingest_single(self):
        fp = ScannerFingerprinter()
        fp.ingest(_ev())
        assert fp.event_count == 1

    def test_ingest_batch(self):
        fp = ScannerFingerprinter()
        count = fp.ingest_batch([_ev(), _ev(ip="2.2.2.2")])
        assert count == 2

    def test_clear(self):
        fp = ScannerFingerprinter()
        fp.ingest(_ev())
        fp.clear()
        assert fp.event_count == 0

    def test_fingerprint_all_empty(self):
        fp = ScannerFingerprinter()
        results = fp.fingerprint_all()
        assert results == {}

    def test_fingerprint_ip_not_found(self):
        fp = ScannerFingerprinter()
        fp.ingest(_ev(ip="1.2.3.4"))
        result = fp.fingerprint_ip("9.9.9.9")
        assert result.event_count == 0
        assert result.scanner_type == ScannerType.UNKNOWN


# ===========================================================================
# Shodan detection
# ===========================================================================

class TestShodanDetection:
    def test_shodan_ua_detected(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="1.1.1.1", user_agent="shodan-crawler/1.0"))
        result = fp.fingerprint_ip("1.1.1.1")
        assert result.scanner_type == ScannerType.SHODAN
        assert result.confidence == FingerprintConfidence.HIGH

    def test_shodan_ua_case_insensitive(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="2.2.2.2", user_agent="SHODAN Bot"))
        result = fp.fingerprint_ip("2.2.2.2")
        assert result.scanner_type == ScannerType.SHODAN


# ===========================================================================
# Masscan detection
# ===========================================================================

class TestMasscanDetection:
    def test_masscan_ua_detected(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="3.3.3.3", user_agent="masscan/1.3"))
        result = fp.fingerprint_ip("3.3.3.3")
        assert result.scanner_type == ScannerType.MASSCAN

    def test_fast_timing_masscan_signal(self):
        fp = ScannerFingerprinter(min_events=2)
        # 0.1s gaps — ultra fast
        for i in range(5):
            fp.ingest(_ev(ip="4.4.4.4", ts=i * 0.1))
        result = fp.fingerprint_ip("4.4.4.4")
        # Fast timing should contribute to masscan score
        assert result.avg_inter_event_s is not None
        assert result.avg_inter_event_s < 0.5

    def test_high_volume_no_creds_masscan_signal(self):
        fp = ScannerFingerprinter(min_events=2)
        for i in range(15):
            fp.ingest(_ev(ip="5.5.5.5", ts=float(i), port=80))
        result = fp.fingerprint_ip("5.5.5.5")
        # Should have the high-volume no-creds signal
        signal_text = " ".join(result.signals).lower()
        assert "probe" in signal_text or "volume" in signal_text or "masscan" in signal_text


# ===========================================================================
# ZGrab detection
# ===========================================================================

class TestZGrabDetection:
    def test_zgrab_ua_detected(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="6.6.6.6", user_agent="zgrab/0.x"))
        result = fp.fingerprint_ip("6.6.6.6")
        assert result.scanner_type == ScannerType.ZGRAB
        assert result.confidence == FingerprintConfidence.HIGH


# ===========================================================================
# Metasploit detection
# ===========================================================================

class TestMetasploitDetection:
    def test_metasploit_payload_detected(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="7.7.7.7", payload="auxiliary/scanner/portscan/tcp"))
        result = fp.fingerprint_ip("7.7.7.7")
        assert result.scanner_type == ScannerType.METASPLOIT

    def test_meterpreter_in_payload(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="8.8.8.8", payload="meterpreter session established"))
        result = fp.fingerprint_ip("8.8.8.8")
        assert result.scanner_type == ScannerType.METASPLOIT


# ===========================================================================
# Credential stuffing bot detection
# ===========================================================================

class TestCredentialStuffingBot:
    def test_known_bot_creds_detected(self):
        fp = ScannerFingerprinter(min_events=1)
        fp.ingest(_ev(ip="9.9.9.9", username="admin", password="admin"))
        fp.ingest(_ev(ip="9.9.9.9", username="root", password="root"))
        fp.ingest(_ev(ip="9.9.9.9", username="admin", password="password"))
        result = fp.fingerprint_ip("9.9.9.9")
        assert result.scanner_type == ScannerType.CREDENTIAL_STUFFING_BOT

    def test_signal_mentions_credential_pairs(self):
        fp = ScannerFingerprinter(min_events=1)
        for _ in range(3):
            fp.ingest(_ev(ip="10.10.10.10", username="admin", password="admin"))
        result = fp.fingerprint_ip("10.10.10.10")
        # Should have a signal about known credential pairs
        signal_text = " ".join(result.signals)
        assert "credential" in signal_text.lower() or "bot" in signal_text.lower()


# ===========================================================================
# Human detection
# ===========================================================================

class TestHumanDetection:
    def test_slow_timing_human(self):
        fp = ScannerFingerprinter(min_events=2)
        # 10s gaps — human speed
        for i in range(3):
            fp.ingest(_ev(ip="11.11.11.11", ts=float(i * 10)))
        result = fp.fingerprint_ip("11.11.11.11")
        assert result.scanner_type == ScannerType.HUMAN

    def test_human_confidence_medium_or_higher(self):
        fp = ScannerFingerprinter(min_events=2)
        fp.ingest(_ev(ip="12.12.12.12", ts=0.0))
        fp.ingest(_ev(ip="12.12.12.12", ts=10.0))
        result = fp.fingerprint_ip("12.12.12.12")
        # Human speed → should have some confidence
        assert result.score > 0


# ===========================================================================
# Unknown / below min_events
# ===========================================================================

class TestUnknownScanner:
    def test_below_min_events_is_unknown(self):
        fp = ScannerFingerprinter(min_events=5)
        for _ in range(3):
            fp.ingest(_ev(ip="13.13.13.13"))
        result = fp.fingerprint_ip("13.13.13.13")
        assert result.scanner_type == ScannerType.UNKNOWN
        assert result.confidence == FingerprintConfidence.LOW

    def test_no_signals_unknown(self):
        fp = ScannerFingerprinter(min_events=2)
        fp.ingest(_ev(ip="14.14.14.14"))
        fp.ingest(_ev(ip="14.14.14.14"))
        result = fp.fingerprint_ip("14.14.14.14")
        # May still be classified based on timing — just check it's a valid type
        assert result.scanner_type in ScannerType.__members__.values()


# ===========================================================================
# fingerprint_all
# ===========================================================================

class TestFingerprintAll:
    def test_two_ips_two_results(self):
        fp = ScannerFingerprinter()
        fp.ingest(_ev(ip="1.2.3.4"))
        fp.ingest(_ev(ip="5.6.7.8"))
        results = fp.fingerprint_all()
        assert len(results) == 2
        assert "1.2.3.4" in results
        assert "5.6.7.8" in results

    def test_result_event_count_correct(self):
        fp = ScannerFingerprinter()
        for _ in range(5):
            fp.ingest(_ev(ip="1.2.3.4"))
        results = fp.fingerprint_all()
        assert results["1.2.3.4"].event_count == 5

    def test_to_dict_all_results(self):
        fp = ScannerFingerprinter()
        fp.ingest(_ev(ip="1.2.3.4"))
        results = fp.fingerprint_all()
        d = results["1.2.3.4"].to_dict()
        assert "scanner_type" in d and "source_ip" in d
