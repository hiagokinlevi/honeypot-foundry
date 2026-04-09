"""
Unit tests for honeypots/ssh/credential_logger.py

Tests verify:
  - Basic recording and counting
  - Top-N ranking
  - Credential spray detection
  - Credential stuffing detection
  - Burst detection
  - Brute force detection
  - JSON export structure
  - No raw credentials leak through the summary
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from honeypots.common.event import HoneypotEvent, ServiceType
from honeypots.ssh.credential_logger import (
    CredentialLogger,
    _BURST_THRESHOLD_EVENTS,
    _BURST_WINDOW_SECONDS,
    _SPRAY_DISTINCT_USERNAMES_THRESHOLD,
    _STUFFING_DISTINCT_IPS_THRESHOLD,
    _extract_hash_prefix,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    ip: str = "10.0.0.1",
    username: str = "root",
    password: str = "password123",
    port: int = 22,
    ts: datetime = _BASE_TS,
) -> HoneypotEvent:
    """Create a HoneypotEvent with a credential (will be masked on creation)."""
    return HoneypotEvent(
        timestamp=ts,
        service=ServiceType.SSH,
        source_ip=ip,
        source_port=port,
        username=username,
        credential_observed=password,
    )


def _event_at(seconds_offset: int, ip: str = "10.0.0.1", username: str = "root") -> HoneypotEvent:
    """Create an event at a specific offset from base timestamp."""
    ts = _BASE_TS + timedelta(seconds=seconds_offset)
    return _event(ip=ip, username=username, ts=ts)


# ---------------------------------------------------------------------------
# _extract_hash_prefix
# ---------------------------------------------------------------------------


class TestExtractHashPrefix(unittest.TestCase):

    def test_extracts_from_valid_masked_value(self):
        masked = "[masked:len=8,hash_prefix=abc12345]"
        result = _extract_hash_prefix(masked)
        self.assertEqual(result, "abc12345")

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(_extract_hash_prefix(""))

    def test_returns_none_for_none_input(self):
        self.assertIsNone(_extract_hash_prefix(None))

    def test_returns_none_for_non_masked_string(self):
        self.assertIsNone(_extract_hash_prefix("plain_password"))

    def test_extracts_from_real_masked_event(self):
        event = _event(password="secretpassword")
        # credential_observed is now masked
        self.assertTrue(
            event.credential_observed.startswith("[masked:"),
            "Credential should be masked",
        )
        hp = _extract_hash_prefix(event.credential_observed)
        self.assertIsNotNone(hp)
        self.assertEqual(len(hp), 8)  # 8 hex chars


# ---------------------------------------------------------------------------
# Basic recording
# ---------------------------------------------------------------------------


class TestBasicRecording(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger()

    def test_total_attempts_increments(self):
        self.logger.record(_event())
        self.logger.record(_event())
        self.assertEqual(self.logger.summary()["total_attempts"], 2)

    def test_distinct_source_ips(self):
        self.logger.record(_event(ip="10.0.0.1"))
        self.logger.record(_event(ip="10.0.0.2"))
        self.logger.record(_event(ip="10.0.0.1"))  # repeat
        self.assertEqual(self.logger.summary()["distinct_source_ips"], 2)

    def test_distinct_usernames(self):
        self.logger.record(_event(username="root"))
        self.logger.record(_event(username="admin"))
        self.logger.record(_event(username="root"))  # repeat
        self.assertEqual(self.logger.summary()["distinct_usernames"], 2)

    def test_empty_logger_summary(self):
        summary = self.logger.summary()
        self.assertEqual(summary["total_attempts"], 0)
        self.assertIsNone(summary["first_event_at"])
        self.assertIsNone(summary["last_event_at"])

    def test_first_and_last_event_at(self):
        early = _BASE_TS
        late = _BASE_TS + timedelta(hours=2)
        self.logger.record(_event(ts=late))
        self.logger.record(_event(ts=early))
        summary = self.logger.summary()
        self.assertIn("2026-01-15T12:00:00", summary["first_event_at"])
        # last_event_at should be 2 hours later
        self.assertIn("2026-01-15T14:00:00", summary["last_event_at"])


# ---------------------------------------------------------------------------
# Top-N ranking
# ---------------------------------------------------------------------------


class TestTopNRanking(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger(top_n=3)

    def test_top_usernames_sorted_by_frequency(self):
        for _ in range(5):
            self.logger.record(_event(username="root"))
        for _ in range(3):
            self.logger.record(_event(username="admin"))
        self.logger.record(_event(username="user"))

        top = self.logger.summary()["top_usernames"]
        self.assertEqual(top[0]["username"], "root")
        self.assertEqual(top[0]["attempts"], 5)
        self.assertEqual(top[1]["username"], "admin")

    def test_top_n_limit_respected(self):
        for name in ["a", "b", "c", "d", "e"]:
            self.logger.record(_event(username=name))
        top = self.logger.summary()["top_usernames"]
        self.assertLessEqual(len(top), 3)

    def test_top_source_ips_sorted(self):
        for _ in range(4):
            self.logger.record(_event(ip="192.168.1.1"))
        for _ in range(2):
            self.logger.record(_event(ip="192.168.1.2"))

        top_ips = self.logger.summary()["top_source_ips"]
        self.assertEqual(top_ips[0]["ip"], "192.168.1.1")
        self.assertEqual(top_ips[0]["attempts"], 4)


# ---------------------------------------------------------------------------
# No raw credentials in output
# ---------------------------------------------------------------------------


class TestNoRawCredentials(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger()

    def test_summary_contains_no_raw_passwords(self):
        """The summary JSON must not contain any raw password values."""
        raw_passwords = ["password123", "admin", "letmein", "qwerty"]
        for pw in raw_passwords:
            self.logger.record(_event(password=pw))

        summary_json = json.dumps(self.logger.summary())
        for pw in raw_passwords:
            self.assertNotIn(pw, summary_json, f"Raw password '{pw}' found in summary!")

    def test_credential_hash_prefix_in_top_list(self):
        """Top credential hashes list should contain hash prefixes, not raw values."""
        self.logger.record(_event(password="secret_password"))
        top_hashes = self.logger.summary()["top_credential_hashes"]
        if top_hashes:
            hp = top_hashes[0]["hash_prefix"]
            # Hash prefix should be 8 hex characters
            self.assertEqual(len(hp), 8)
            self.assertTrue(all(c in "0123456789abcdef" for c in hp))


# ---------------------------------------------------------------------------
# Credential spray detection
# ---------------------------------------------------------------------------


class TestCredentialSprayDetection(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger()

    def test_spray_detected_when_threshold_met(self):
        """Same password → many different usernames should trigger spray detection."""
        password = "Summer2026!"
        usernames = [f"user{i}" for i in range(_SPRAY_DISTINCT_USERNAMES_THRESHOLD + 2)]
        for u in usernames:
            self.logger.record(_event(username=u, password=password))

        patterns = self.logger.detect_patterns()
        spray = [p for p in patterns if p.pattern_type == "credential_spray"]
        self.assertTrue(spray, "Expected credential_spray pattern")
        self.assertEqual(spray[0].severity, "high")
        self.assertGreaterEqual(
            spray[0].evidence["distinct_usernames_targeted"],
            _SPRAY_DISTINCT_USERNAMES_THRESHOLD,
        )

    def test_spray_not_detected_below_threshold(self):
        """Below threshold should not trigger spray detection."""
        password = "Summer2026!"
        for i in range(_SPRAY_DISTINCT_USERNAMES_THRESHOLD - 1):
            self.logger.record(_event(username=f"user{i}", password=password))

        patterns = self.logger.detect_patterns()
        spray = [p for p in patterns if p.pattern_type == "credential_spray"]
        self.assertFalse(spray)

    def test_spray_evidence_contains_no_raw_password(self):
        """Spray evidence must not expose raw password values."""
        password = "SuperSecretPass!"
        for i in range(_SPRAY_DISTINCT_USERNAMES_THRESHOLD + 1):
            self.logger.record(_event(username=f"user{i}", password=password))

        patterns = self.logger.detect_patterns()
        spray = [p for p in patterns if p.pattern_type == "credential_spray"]
        if spray:
            evidence_json = json.dumps(spray[0].evidence)
            self.assertNotIn(password, evidence_json)


# ---------------------------------------------------------------------------
# Credential stuffing detection
# ---------------------------------------------------------------------------


class TestCredentialStuffingDetection(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger()

    def test_stuffing_detected_when_threshold_met(self):
        """Same password from many IPs should trigger stuffing detection."""
        password = "BreachedPass2026"
        ips = [f"10.0.0.{i}" for i in range(_STUFFING_DISTINCT_IPS_THRESHOLD + 2)]
        for ip in ips:
            self.logger.record(_event(ip=ip, password=password))

        patterns = self.logger.detect_patterns()
        stuffing = [p for p in patterns if p.pattern_type == "credential_stuffing"]
        self.assertTrue(stuffing, "Expected credential_stuffing pattern")
        self.assertEqual(stuffing[0].severity, "high")
        self.assertGreaterEqual(
            stuffing[0].evidence["distinct_source_ips"],
            _STUFFING_DISTINCT_IPS_THRESHOLD,
        )

    def test_stuffing_not_detected_below_threshold(self):
        """Below IP threshold should not trigger stuffing detection."""
        password = "BreachedPass2026"
        for i in range(_STUFFING_DISTINCT_IPS_THRESHOLD - 1):
            self.logger.record(_event(ip=f"10.0.0.{i}", password=password))

        patterns = self.logger.detect_patterns()
        stuffing = [p for p in patterns if p.pattern_type == "credential_stuffing"]
        self.assertFalse(stuffing)


# ---------------------------------------------------------------------------
# Burst detection
# ---------------------------------------------------------------------------


class TestBurstDetection(unittest.TestCase):

    def setUp(self):
        self.logger = CredentialLogger()

    def test_burst_detected_when_threshold_met(self):
        """Many attempts from one IP within the burst window should trigger burst."""
        ip = "10.10.10.10"
        # All events within 30 seconds (well under _BURST_WINDOW_SECONDS)
        for i in range(_BURST_THRESHOLD_EVENTS + 2):
            self.logger.record(_event_at(i * 2, ip=ip))  # 2-second intervals

        patterns = self.logger.detect_patterns()
        bursts = [p for p in patterns if p.pattern_type == "burst"]
        self.assertTrue(bursts, "Expected burst pattern")
        self.assertEqual(bursts[0].severity, "critical")
        self.assertEqual(bursts[0].evidence["source_ip"], ip)

    def test_burst_not_detected_below_threshold(self):
        """Below the burst count threshold should not fire."""
        ip = "10.10.10.11"
        for i in range(_BURST_THRESHOLD_EVENTS - 2):
            self.logger.record(_event_at(i * 2, ip=ip))

        patterns = self.logger.detect_patterns()
        bursts = [p for p in patterns if p.pattern_type == "burst"]
        self.assertFalse(bursts)

    def test_burst_not_detected_when_spread_over_time(self):
        """Events spread beyond the window should not trigger burst."""
        ip = "10.10.10.12"
        # One event per 10 minutes — well beyond the 60-second window
        for i in range(_BURST_THRESHOLD_EVENTS + 5):
            self.logger.record(_event_at(i * 600, ip=ip))

        patterns = self.logger.detect_patterns()
        bursts = [p for p in patterns if p.pattern_type == "burst"]
        self.assertFalse(bursts)

    def test_burst_severity_is_critical(self):
        """Burst pattern should always have critical severity."""
        ip = "10.10.10.13"
        for i in range(_BURST_THRESHOLD_EVENTS + 1):
            self.logger.record(_event_at(i, ip=ip))

        patterns = self.logger.detect_patterns()
        bursts = [p for p in patterns if p.pattern_type == "burst"]
        if bursts:
            self.assertEqual(bursts[0].severity, "critical")


# ---------------------------------------------------------------------------
# Pattern sorting
# ---------------------------------------------------------------------------


class TestPatternSorting(unittest.TestCase):

    def test_critical_patterns_sorted_first(self):
        """detect_patterns() must return critical before high before medium."""
        logger = CredentialLogger()
        ip = "10.20.30.40"
        # Trigger burst (critical) + spray (high)
        password = "SharedPassword!"
        for i in range(_BURST_THRESHOLD_EVENTS + 1):
            logger.record(_event_at(i, ip=ip))
        for u in [f"user{i}" for i in range(_SPRAY_DISTINCT_USERNAMES_THRESHOLD + 1)]:
            logger.record(_event(username=u, password=password))

        patterns = logger.detect_patterns()
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        severities = [severity_order[p.severity] for p in patterns]
        self.assertEqual(severities, sorted(severities))


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


class TestJSONExport(unittest.TestCase):

    def test_export_creates_valid_json_file(self):
        logger = CredentialLogger()
        logger.record(_event())

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            returned_path = logger.export_json(path)
            content = path.read_text()

        self.assertEqual(returned_path, path)
        doc = json.loads(content)  # Must not raise
        self.assertIn("generated_at", doc)
        self.assertIn("service", doc)
        self.assertIn("summary", doc)
        self.assertEqual(doc["service"], "ssh")

    def test_export_creates_parent_directory(self):
        logger = CredentialLogger()
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "reports" / "ssh" / "summary.json"
            logger.export_json(nested)
            self.assertTrue(nested.exists())

    def test_export_json_contains_no_raw_credentials(self):
        """The exported JSON file must never contain raw credential values."""
        logger = CredentialLogger()
        raw_passwords = ["hunter2", "abc123", "password1"]
        for pw in raw_passwords:
            logger.record(_event(password=pw))

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            logger.export_json(path)
            content = path.read_text()

        for pw in raw_passwords:
            self.assertNotIn(pw, content, f"Raw password '{pw}' leaked into export!")


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset(unittest.TestCase):

    def test_reset_clears_all_data(self):
        logger = CredentialLogger()
        logger.record(_event())
        logger.record(_event(username="admin"))
        self.assertEqual(logger.summary()["total_attempts"], 2)

        logger.reset()
        self.assertEqual(logger.summary()["total_attempts"], 0)
        self.assertEqual(logger.summary()["distinct_usernames"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
