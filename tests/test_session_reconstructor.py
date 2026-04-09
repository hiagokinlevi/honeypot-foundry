"""
Tests for analysis/session_reconstructor.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.session_reconstructor import (
    AttackPhase,
    AttackSession,
    SessionReconstructor,
    SessionReport,
    SessionSeverity,
    _classify_phase,
    _compute_score,
    _parse_ts,
    _score_to_severity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ts(offset_seconds: float = 0) -> str:
    """Return a UTC ISO timestamp offset from a fixed base."""
    base = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def _event(
    ip: str = "1.2.3.4",
    ts_offset: float = 0,
    event_type: str = "auth_fail",
    username: str = "",
    password: str = "",
    service: str = "ssh",
    success: bool = False,
) -> dict:
    e: dict = {
        "source_ip": ip,
        "timestamp": _ts(ts_offset),
        "event_type": event_type,
        "service": service,
    }
    if username:
        e["username"] = username
    if password:
        e["password"] = password
    if success:
        e["success"] = True
    return e


# ===========================================================================
# _parse_ts
# ===========================================================================

class TestParseTs:
    def test_iso_string(self):
        dt = _parse_ts({"timestamp": "2026-04-01T10:00:00+00:00"})
        assert dt is not None

    def test_unix_int(self):
        dt = _parse_ts({"ts": 1_700_000_000})
        assert dt is not None

    def test_unix_float(self):
        dt = _parse_ts({"ts": 1_700_000_000.5})
        assert dt is not None

    def test_no_timestamp(self):
        dt = _parse_ts({})
        assert dt is None

    def test_invalid_string(self):
        dt = _parse_ts({"timestamp": "not-a-date"})
        assert dt is None

    def test_alternative_key(self):
        dt = _parse_ts({"event_time": _ts()})
        assert dt is not None


# ===========================================================================
# AttackSession
# ===========================================================================

class TestAttackSession:
    def _session(self, **kwargs) -> AttackSession:
        s = AttackSession(session_id="1.2.3.4-0", source_ip="1.2.3.4", **kwargs)
        s.start_time = _ts(0)
        s.end_time   = _ts(60)
        return s

    def test_event_count(self):
        s = self._session(events=[{}, {}])
        assert s.event_count == 2

    def test_duration_seconds(self):
        s = self._session()
        assert abs(s.duration_seconds - 60.0) < 1

    def test_duration_zero_when_no_times(self):
        s = AttackSession(session_id="x", source_ip="1.2.3.4")
        assert s.duration_seconds == 0.0

    def test_summary_contains_session_id(self):
        s = self._session()
        s.phase      = AttackPhase.BRUTE_FORCE
        s.risk_score = 50
        s.severity   = SessionSeverity.MEDIUM
        assert "1.2.3.4-0" in s.summary()

    def test_to_dict_has_required_keys(self):
        s = self._session()
        d = s.to_dict()
        for key in ("session_id", "source_ip", "phase", "risk_score", "severity"):
            assert key in d


# ===========================================================================
# _classify_phase
# ===========================================================================

class TestClassifyPhase:
    def _session_with(self, **kwargs) -> AttackSession:
        s = AttackSession(session_id="s", source_ip="x")
        for k, v in kwargs.items():
            setattr(s, k, v)
        return s

    def test_exploitation_when_successful_auth(self):
        s = self._session_with(successful_auths=1, unique_usernames={"root"})
        phase, indicators = _classify_phase(s)
        assert phase == AttackPhase.EXPLOITATION
        assert indicators

    def test_spray_many_usernames_few_passwords(self):
        s = self._session_with(
            events=[{}] * 20,
            unique_usernames={f"user{i}" for i in range(15)},
            unique_passwords={"pass1"},
        )
        phase, _ = _classify_phase(s)
        assert phase == AttackPhase.CREDENTIAL_SPRAY

    def test_stuffing_many_usernames_many_passwords(self):
        s = self._session_with(
            events=[{}] * 30,
            unique_usernames={f"u{i}" for i in range(10)},
            unique_passwords={f"p{i}" for i in range(10)},
        )
        phase, _ = _classify_phase(s)
        assert phase == AttackPhase.CREDENTIAL_STUFFING

    def test_brute_force_high_volume_few_users(self):
        s = self._session_with(
            events=[{}] * 30,
            unique_usernames={"root"},
            unique_passwords={"p1", "p2"},
        )
        phase, _ = _classify_phase(s)
        assert phase == AttackPhase.BRUTE_FORCE

    def test_recon_no_credentials(self):
        s = self._session_with(
            events=[{}] * 5,
            services={"ssh"},
        )
        phase, _ = _classify_phase(s)
        assert phase == AttackPhase.RECONNAISSANCE

    def test_unknown_no_signals(self):
        s = self._session_with()
        phase, _ = _classify_phase(s)
        assert phase == AttackPhase.UNKNOWN


# ===========================================================================
# _compute_score
# ===========================================================================

class TestComputeScore:
    def _session(self, phase: AttackPhase, events=5, auths_ok=0, services=1) -> AttackSession:
        s = AttackSession(session_id="s", source_ip="x")
        s.phase           = phase
        s.events          = [{}] * events
        s.successful_auths = auths_ok
        s.services        = {f"svc{i}" for i in range(services)}
        return s

    def test_exploitation_has_high_base(self):
        score = _compute_score(self._session(AttackPhase.EXPLOITATION, auths_ok=1))
        assert score >= 60

    def test_unknown_has_low_base(self):
        score = _compute_score(self._session(AttackPhase.UNKNOWN))
        assert score < 30

    def test_score_capped_at_100(self):
        score = _compute_score(
            self._session(AttackPhase.EXPLOITATION, events=1000, auths_ok=100, services=10)
        )
        assert score == 100

    def test_multi_service_adds_bonus(self):
        score_single = _compute_score(self._session(AttackPhase.BRUTE_FORCE, services=1))
        score_multi  = _compute_score(self._session(AttackPhase.BRUTE_FORCE, services=3))
        assert score_multi > score_single


# ===========================================================================
# _score_to_severity
# ===========================================================================

class TestScoreToSeverity:
    def test_critical(self):
        assert _score_to_severity(80) == SessionSeverity.CRITICAL

    def test_high(self):
        assert _score_to_severity(60) == SessionSeverity.HIGH

    def test_medium(self):
        assert _score_to_severity(40) == SessionSeverity.MEDIUM

    def test_low(self):
        assert _score_to_severity(20) == SessionSeverity.LOW

    def test_info(self):
        assert _score_to_severity(10) == SessionSeverity.INFO


# ===========================================================================
# SessionReconstructor
# ===========================================================================

class TestSessionReconstructor:
    def test_ingest_single(self):
        recon = SessionReconstructor()
        recon.ingest(_event())
        assert recon.event_count == 1

    def test_ingest_batch(self):
        recon = SessionReconstructor()
        count = recon.ingest_batch([_event(), _event(ip="5.5.5.5")])
        assert count == 2

    def test_clear(self):
        recon = SessionReconstructor()
        recon.ingest(_event())
        recon.clear()
        assert recon.event_count == 0

    def test_empty_reconstruct(self):
        recon = SessionReconstructor()
        report = recon.reconstruct()
        assert report.total_events == 0
        assert report.session_count == 0

    def test_single_session(self):
        recon = SessionReconstructor()
        for i in range(5):
            recon.ingest(_event(ip="1.2.3.4", ts_offset=i * 10))
        report = recon.reconstruct()
        assert report.session_count == 1

    def test_two_ips_two_sessions(self):
        recon = SessionReconstructor()
        recon.ingest(_event(ip="1.1.1.1"))
        recon.ingest(_event(ip="2.2.2.2"))
        report = recon.reconstruct()
        assert report.unique_source_ips == 2
        assert report.session_count == 2

    def test_idle_gap_splits_sessions(self):
        recon = SessionReconstructor(session_timeout_s=60)
        recon.ingest(_event(ip="1.2.3.4", ts_offset=0))
        recon.ingest(_event(ip="1.2.3.4", ts_offset=200))  # gap > 60s
        report = recon.reconstruct()
        assert report.session_count == 2

    def test_brute_force_classification(self):
        recon = SessionReconstructor()
        for i in range(25):
            recon.ingest(_event(
                ip="5.5.5.5",
                ts_offset=i * 5,
                username="root",
                event_type="auth_fail",
            ))
        report = recon.reconstruct()
        session = report.sessions[0]
        assert session.phase == AttackPhase.BRUTE_FORCE

    def test_spray_classification(self):
        recon = SessionReconstructor()
        for i in range(15):
            recon.ingest(_event(
                ip="6.6.6.6",
                ts_offset=i * 3,
                username=f"user{i}",
                password="password123",
                event_type="auth_fail",
            ))
        report = recon.reconstruct()
        assert report.sessions[0].phase == AttackPhase.CREDENTIAL_SPRAY

    def test_exploitation_after_success(self):
        recon = SessionReconstructor()
        recon.ingest(_event(ip="7.7.7.7", event_type="auth_success", success=True, username="admin"))
        report = recon.reconstruct()
        assert report.sessions[0].phase == AttackPhase.EXPLOITATION

    def test_critical_sessions_aggregated(self):
        recon = SessionReconstructor()
        recon.ingest(_event(ip="9.9.9.9", event_type="auth_success", success=True))
        report = recon.reconstruct()
        # success → EXPLOITATION → score ≥ 60 → at least HIGH
        assert report.sessions[0].severity in (SessionSeverity.CRITICAL, SessionSeverity.HIGH)

    def test_report_total_events(self):
        recon = SessionReconstructor()
        recon.ingest_batch([_event() for _ in range(7)])
        report = recon.reconstruct()
        assert report.total_events == 7

    def test_report_summary(self):
        recon = SessionReconstructor()
        recon.ingest(_event())
        report = recon.reconstruct()
        assert "1" in report.summary()

    def test_top_sessions_limit(self):
        recon = SessionReconstructor()
        for i in range(5):
            recon.ingest(_event(ip=f"10.0.0.{i}"))
        report = recon.reconstruct()
        top = report.top_sessions(n=2)
        assert len(top) == 2

    def test_event_without_timestamp(self):
        recon = SessionReconstructor()
        recon.ingest({"source_ip": "1.2.3.4", "event_type": "auth_fail"})  # no timestamp
        report = recon.reconstruct()
        assert report.session_count == 1

    def test_session_to_dict(self):
        recon = SessionReconstructor()
        recon.ingest(_event())
        report = recon.reconstruct()
        d = report.sessions[0].to_dict()
        assert "session_id" in d and "phase" in d and "risk_score" in d
