"""
Attack Session Reconstructor
==============================
Groups raw honeypot events by source IP and time window to reconstruct
attacker sessions and classify the attack phase and intent.

An "attack session" is a sequence of events from the same source IP
within a configurable idle timeout. The reconstructor:

  1. Groups events into sessions (idle gap > ``session_timeout_s`` splits sessions).
  2. Classifies each session into an attack phase:
       RECONNAISSANCE  — scans, probes, banner grabs with no credentials
       CREDENTIAL_SPRAY — credential attempts across many usernames
       CREDENTIAL_STUFFING — same credential set replayed from one IP
       BRUTE_FORCE — high-volume single-target credential guessing
       EXPLOITATION — successful auth, command execution, file access
       UNKNOWN — insufficient signals
  3. Scores each session 0–100 (CRITICAL / HIGH / MEDIUM / LOW / INFO).
  4. Produces a SessionReport for export and SIEM forwarding.

Usage::

    from analysis.session_reconstructor import SessionReconstructor

    recon = SessionReconstructor(session_timeout_s=300)
    for event in raw_events:
        recon.ingest(event)
    report = recon.reconstruct()
    for session in report.sessions:
        print(session.summary())
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AttackPhase(str, Enum):
    RECONNAISSANCE      = "RECONNAISSANCE"
    CREDENTIAL_SPRAY    = "CREDENTIAL_SPRAY"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    BRUTE_FORCE         = "BRUTE_FORCE"
    EXPLOITATION        = "EXPLOITATION"
    UNKNOWN             = "UNKNOWN"


class SessionSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # score >= 80
    HIGH     = "HIGH"       # score >= 60
    MEDIUM   = "MEDIUM"     # score >= 40
    LOW      = "LOW"        # score >= 20
    INFO     = "INFO"       # score < 20


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AttackSession:
    """
    A reconstructed attacker session.

    Attributes:
        session_id:        Unique session identifier (``<ip>-<index>``).
        source_ip:         Source IP address.
        events:            Ordered list of raw event dicts in this session.
        start_time:        Timestamp of the first event (ISO 8601, UTC).
        end_time:          Timestamp of the last event (ISO 8601, UTC).
        phase:             Classified attack phase.
        risk_score:        Integer 0–100.
        severity:          Derived severity bucket.
        unique_usernames:  Set of usernames observed in auth attempts.
        unique_passwords:  Set of passwords observed (plain or hashed).
        successful_auths:  Number of events flagged as successful logins.
        services:          Set of target service names (e.g. "ssh", "http").
        indicators:        List of human-readable phase indicator strings.
    """
    session_id:       str
    source_ip:        str
    events:           list[dict[str, Any]] = field(default_factory=list)
    start_time:       str = ""
    end_time:         str = ""
    phase:            AttackPhase = AttackPhase.UNKNOWN
    risk_score:       int = 0
    severity:         SessionSeverity = SessionSeverity.INFO
    unique_usernames: set[str] = field(default_factory=set)
    unique_passwords: set[str] = field(default_factory=set)
    successful_auths: int = 0
    services:         set[str] = field(default_factory=set)
    indicators:       list[str] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def duration_seconds(self) -> float:
        """Total session duration in seconds."""
        if not self.start_time or not self.end_time:
            return 0.0
        try:
            start = datetime.fromisoformat(self.start_time)
            end   = datetime.fromisoformat(self.end_time)
            return max(0.0, (end - start).total_seconds())
        except ValueError:
            return 0.0

    def summary(self) -> str:
        return (
            f"[{self.severity.value}] {self.session_id} | "
            f"phase={self.phase.value} score={self.risk_score} | "
            f"{self.event_count} events over {self.duration_seconds:.0f}s | "
            f"users={len(self.unique_usernames)} auths_ok={self.successful_auths}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id":       self.session_id,
            "source_ip":        self.source_ip,
            "start_time":       self.start_time,
            "end_time":         self.end_time,
            "event_count":      self.event_count,
            "duration_seconds": self.duration_seconds,
            "phase":            self.phase.value,
            "risk_score":       self.risk_score,
            "severity":         self.severity.value,
            "unique_usernames": sorted(self.unique_usernames),
            "unique_passwords": sorted(self.unique_passwords),
            "successful_auths": self.successful_auths,
            "services":         sorted(self.services),
            "indicators":       self.indicators,
        }


@dataclass
class SessionReport:
    """
    Aggregated report produced by SessionReconstructor.reconstruct().

    Attributes:
        sessions:          All reconstructed sessions.
        total_events:      Total events ingested.
        unique_source_ips: Number of distinct source IPs.
        critical_sessions: Sessions with severity CRITICAL.
        high_sessions:     Sessions with severity HIGH.
    """
    sessions:           list[AttackSession] = field(default_factory=list)
    total_events:       int = 0
    unique_source_ips:  int = 0
    critical_sessions:  list[AttackSession] = field(default_factory=list)
    high_sessions:      list[AttackSession] = field(default_factory=list)

    @property
    def session_count(self) -> int:
        return len(self.sessions)

    def summary(self) -> str:
        return (
            f"SessionReport: {self.session_count} sessions | "
            f"{self.total_events} events | "
            f"{self.unique_source_ips} source IPs | "
            f"CRITICAL={len(self.critical_sessions)} HIGH={len(self.high_sessions)}"
        )

    def top_sessions(self, n: int = 10) -> list[AttackSession]:
        """Return the N highest-risk sessions."""
        return sorted(self.sessions, key=lambda s: s.risk_score, reverse=True)[:n]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ts(event: dict[str, Any]) -> Optional[datetime]:
    """Extract a UTC datetime from an event dict."""
    for key in ("timestamp", "ts", "time", "event_time", "@timestamp"):
        raw = event.get(key)
        if not raw:
            continue
        if isinstance(raw, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        if isinstance(raw, str):
            try:
                dt = datetime.fromisoformat(raw.rstrip("Z"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _get_str(event: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty string value for any of the given keys."""
    for key in keys:
        val = event.get(key)
        if val and isinstance(val, str):
            return val.strip()
    return ""


def _classify_phase(session: AttackSession) -> tuple[AttackPhase, list[str]]:
    """
    Classify the attack phase based on session signals.

    Returns (phase, indicators).
    """
    indicators: list[str] = []

    n_events     = session.event_count
    n_users      = len(session.unique_usernames)
    n_passwords  = len(session.unique_passwords)
    n_auths_ok   = session.successful_auths
    n_services   = len(session.services)

    # Exploitation: any successful authentication
    if n_auths_ok > 0:
        indicators.append(f"{n_auths_ok} successful authentication(s) detected")
        return AttackPhase.EXPLOITATION, indicators

    # Needs credential attempts to distinguish spray/stuffing/brute-force
    has_creds = n_users > 0 or n_passwords > 0

    if has_creds:
        # Credential spray: many distinct usernames, few passwords
        if n_users >= 10 and n_passwords <= 3:
            indicators.append(
                f"Spray pattern: {n_users} usernames with ≤3 passwords"
            )
            return AttackPhase.CREDENTIAL_SPRAY, indicators

        # Credential stuffing: many distinct username:password pairs but
        # the same password appears across many usernames (same hash reuse)
        if n_users >= 5 and n_passwords >= 5:
            indicators.append(
                f"Stuffing pattern: {n_users} users × {n_passwords} passwords"
            )
            return AttackPhase.CREDENTIAL_STUFFING, indicators

        # Brute force: high event volume against few targets
        if n_events >= 20 and n_users <= 3:
            indicators.append(
                f"Brute-force pattern: {n_events} attempts against ≤3 usernames"
            )
            return AttackPhase.BRUTE_FORCE, indicators

        # Low-volume credential attempt — still credential-related
        if n_users > 0:
            indicators.append(
                f"Low-volume auth attempt: {n_events} events, {n_users} username(s)"
            )
            return AttackPhase.BRUTE_FORCE, indicators

    # No credentials — reconnaissance (scan/probe)
    if n_services >= 1:
        indicators.append(
            f"Probe activity: {n_events} events across {n_services} service(s) with no credentials"
        )
        return AttackPhase.RECONNAISSANCE, indicators

    return AttackPhase.UNKNOWN, indicators


def _compute_score(session: AttackSession) -> int:
    """
    Compute a risk score 0–100 for a session.

    Scoring components (additive, capped at 100):
      - phase base score
      - event volume (log scale)
      - successful auths
      - multi-service spread
    """
    phase_base = {
        AttackPhase.EXPLOITATION:        60,
        AttackPhase.BRUTE_FORCE:         40,
        AttackPhase.CREDENTIAL_SPRAY:    35,
        AttackPhase.CREDENTIAL_STUFFING: 35,
        AttackPhase.RECONNAISSANCE:      15,
        AttackPhase.UNKNOWN:              5,
    }
    score = phase_base.get(session.phase, 5)

    # Volume bonus: log2(event_count) capped at 20
    volume_bonus = min(20, int(math.log2(max(1, session.event_count)) * 3))
    score += volume_bonus

    # Successful auth bonus
    if session.successful_auths > 0:
        score += min(20, session.successful_auths * 5)

    # Multi-service spread bonus
    if len(session.services) > 1:
        score += min(10, (len(session.services) - 1) * 5)

    return min(100, score)


def _score_to_severity(score: int) -> SessionSeverity:
    if score >= 80:
        return SessionSeverity.CRITICAL
    if score >= 60:
        return SessionSeverity.HIGH
    if score >= 40:
        return SessionSeverity.MEDIUM
    if score >= 20:
        return SessionSeverity.LOW
    return SessionSeverity.INFO


# ---------------------------------------------------------------------------
# SessionReconstructor
# ---------------------------------------------------------------------------

class SessionReconstructor:
    """
    Groups honeypot events by source IP and time window, reconstructs
    attacker sessions, classifies attack phases, and scores sessions.

    Args:
        session_timeout_s: Idle gap in seconds that splits two sessions.
                           Default: 300 (5 minutes).
    """

    def __init__(self, session_timeout_s: float = 300.0) -> None:
        self._timeout = session_timeout_s
        self._events: list[dict[str, Any]] = []

    def ingest(self, event: dict[str, Any]) -> None:
        """Add a single honeypot event for reconstruction."""
        self._events.append(event)

    def ingest_batch(self, events: list[dict[str, Any]]) -> int:
        """Add multiple events. Returns count ingested."""
        self._events.extend(events)
        return len(events)

    def clear(self) -> None:
        """Discard all ingested events."""
        self._events.clear()

    @property
    def event_count(self) -> int:
        return len(self._events)

    def reconstruct(self) -> SessionReport:
        """
        Reconstruct sessions from all ingested events.

        Returns a SessionReport with classified, scored AttackSessions.
        """
        if not self._events:
            return SessionReport(total_events=0, unique_source_ips=0)

        # Group events by source IP
        by_ip: dict[str, list[dict[str, Any]]] = {}
        for event in self._events:
            ip = _get_str(event, "source_ip", "src_ip", "ip", "remote_ip")
            if not ip:
                ip = "unknown"
            by_ip.setdefault(ip, []).append(event)

        sessions: list[AttackSession] = []

        for ip, ip_events in by_ip.items():
            # Sort events by timestamp; events without timestamps go last
            def sort_key(e: dict[str, Any]) -> float:
                dt = _parse_ts(e)
                return dt.timestamp() if dt else float("inf")

            ip_events.sort(key=sort_key)

            # Split into sessions by idle gap
            session_groups: list[list[dict[str, Any]]] = []
            current_group: list[dict[str, Any]] = [ip_events[0]]
            last_dt = _parse_ts(ip_events[0])

            for event in ip_events[1:]:
                dt = _parse_ts(event)
                if dt and last_dt:
                    gap = (dt - last_dt).total_seconds()
                    if gap > self._timeout:
                        session_groups.append(current_group)
                        current_group = []
                if dt:
                    last_dt = dt
                current_group.append(event)
            session_groups.append(current_group)

            for idx, group in enumerate(session_groups):
                session = self._build_session(
                    session_id=f"{ip}-{idx}",
                    source_ip=ip,
                    events=group,
                )
                sessions.append(session)

        # Build report
        report = SessionReport(
            sessions=sessions,
            total_events=len(self._events),
            unique_source_ips=len(by_ip),
            critical_sessions=[s for s in sessions if s.severity == SessionSeverity.CRITICAL],
            high_sessions=[s for s in sessions if s.severity == SessionSeverity.HIGH],
        )
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_session(
        self,
        session_id: str,
        source_ip: str,
        events: list[dict[str, Any]],
    ) -> AttackSession:
        session = AttackSession(session_id=session_id, source_ip=source_ip)
        session.events = events

        # Extract time bounds
        timestamps = [_parse_ts(e) for e in events]
        valid_ts = [t for t in timestamps if t is not None]
        if valid_ts:
            session.start_time = min(valid_ts).isoformat()
            session.end_time   = max(valid_ts).isoformat()

        # Aggregate signals
        for event in events:
            # Usernames / passwords
            username = _get_str(event, "username", "user", "login")
            if username:
                session.unique_usernames.add(username)

            password = _get_str(event, "password", "credential", "pw")
            if password:
                session.unique_passwords.add(password)

            # Services
            service = _get_str(event, "service", "protocol", "sensor")
            if service:
                session.services.add(service.lower())

            # Successful auth
            event_type = _get_str(event, "event_type", "type", "action")
            success_flag = event.get("success") or event.get("auth_success")
            if success_flag is True or event_type in ("login_success", "auth_success", "authenticated"):
                session.successful_auths += 1

        # Classify phase
        phase, indicators = _classify_phase(session)
        session.phase      = phase
        session.indicators = indicators

        # Score
        score = _compute_score(session)
        session.risk_score = score
        session.severity   = _score_to_severity(score)

        return session
