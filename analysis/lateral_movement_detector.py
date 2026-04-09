# lateral_movement_detector.py
# Part of Cyber Port — Honeypot Foundry
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0) — https://creativecommons.org/licenses/by/4.0/
#
# Analyzes honeypot event streams for lateral movement patterns including
# credential reuse, sequential host access, username enumeration, insider
# threats from internal IPs, and post-compromise reconnaissance.

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Check weights — keyed by check ID
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "LATM-001": 45,  # CRITICAL — credential reuse across multiple source IPs
    "LATM-002": 25,  # HIGH    — same IP hitting >2 distinct honeypot hosts
    "LATM-003": 20,  # HIGH    — username enumeration (>5 distinct usernames)
    "LATM-004": 25,  # HIGH    — source IP is RFC1918/loopback (insider threat)
    "LATM-005": 25,  # HIGH    — post-auth lateral pivot within 5 minutes
    "LATM-006": 15,  # MEDIUM  — failed attempt after prior success (recon)
    "LATM-007": 20,  # HIGH    — burst: >10 events from same IP within 1 minute
}

_SEVERITY: Dict[str, str] = {
    "LATM-001": "CRITICAL",
    "LATM-002": "HIGH",
    "LATM-003": "HIGH",
    "LATM-004": "HIGH",
    "LATM-005": "HIGH",
    "LATM-006": "MEDIUM",
    "LATM-007": "HIGH",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class HoneypotEvent:
    """A single event captured by a honeypot sensor."""

    event_id: str
    source_ip: str
    honeypot_host: str       # e.g. "hp-ssh-01", "hp-http-01"
    username: Optional[str]
    password: Optional[str]
    success: bool            # True if authentication succeeded
    timestamp_ms: int        # Unix milliseconds


@dataclass
class LATMFinding:
    """A single lateral-movement finding produced by a check."""

    check_id: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    source_ips: List[str]    # IPs involved in this finding
    event_ids: List[str]     # event IDs that triggered this finding


@dataclass
class LATMResult:
    """Aggregated result for a batch of honeypot events."""

    findings: List[LATMFinding]
    risk_score: int          # min(100, sum of weights for unique fired check IDs)
    threat_level: str        # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"

    def to_dict(self) -> dict:
        """Serialise the result to a plain Python dict (JSON-safe)."""
        return {
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "source_ips": f.source_ips,
                    "event_ids": f.event_ids,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        return (
            f"[{self.threat_level}] risk_score={self.risk_score} "
            f"findings={len(self.findings)}"
        )

    def by_severity(self) -> dict:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[LATMFinding]] = defaultdict(list)
        for finding in self.findings:
            groups[finding.severity].append(finding)
        return dict(groups)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# RFC1918 private ranges + loopback
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_internal_ip(ip: str) -> bool:
    """Return True for RFC1918 private addresses and loopback (127.x)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False  # malformed addresses are treated as external
    return any(addr in net for net in _INTERNAL_NETWORKS)


def _events_in_window(events: List[HoneypotEvent], window_ms: int) -> bool:
    """Return True if any contiguous sub-list of *events* fits within window_ms.

    Events are sorted by timestamp internally; the caller does not need to
    pre-sort. Uses a two-pointer (sliding-window) approach for O(n) amortised
    performance.
    """
    if len(events) < 2:
        return False  # a single event always fits; caller must check count
    sorted_events = sorted(events, key=lambda e: e.timestamp_ms)
    left = 0
    for right in range(len(sorted_events)):
        # Shrink window from the left until it fits within window_ms
        while (
            sorted_events[right].timestamp_ms - sorted_events[left].timestamp_ms
            > window_ms
        ):
            left += 1
        if right - left + 1 >= 2:  # at least 2 events inside this window
            return True
    return False


def _find_window_events(
    events: List[HoneypotEvent], window_ms: int, min_count: int
) -> Optional[List[HoneypotEvent]]:
    """Return the events in the first window of *window_ms* that contains at
    least *min_count* events, or None if no such window exists.

    Events are sorted by timestamp internally.
    """
    if len(events) < min_count:
        return None
    sorted_events = sorted(events, key=lambda e: e.timestamp_ms)
    left = 0
    for right in range(len(sorted_events)):
        while (
            sorted_events[right].timestamp_ms - sorted_events[left].timestamp_ms
            > window_ms
        ):
            left += 1
        if right - left + 1 >= min_count:
            return sorted_events[left : right + 1]
    return None


def _compute_risk(fired_check_ids: List[str]) -> int:
    """Sum the weights of unique check IDs, capped at 100."""
    return min(100, sum(_CHECK_WEIGHTS[cid] for cid in set(fired_check_ids)))


def _threat_level(score: int) -> str:
    """Map a numeric risk score to a threat level label."""
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_latm001(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-001: Same credential used from >1 source IP within 1 hour."""
    ONE_HOUR_MS = 60 * 60 * 1000

    # Group events by (username, password) — skip events with None credentials
    cred_events: Dict[Tuple[str, str], List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        if ev.username is not None and ev.password is not None:
            cred_events[(ev.username, ev.password)].append(ev)

    findings: List[LATMFinding] = []
    for (username, password), cred_evs in cred_events.items():
        # Sort by timestamp
        sorted_evs = sorted(cred_evs, key=lambda e: e.timestamp_ms)
        # Sliding window: find any 1-hour window with >1 distinct source IP
        left = 0
        for right in range(len(sorted_evs)):
            while (
                sorted_evs[right].timestamp_ms - sorted_evs[left].timestamp_ms
                > ONE_HOUR_MS
            ):
                left += 1
            window = sorted_evs[left : right + 1]
            distinct_ips = set(e.source_ip for e in window)
            if len(distinct_ips) > 1:
                # Fire finding for this credential pair
                findings.append(
                    LATMFinding(
                        check_id="LATM-001",
                        severity=_SEVERITY["LATM-001"],
                        title="Credential reuse across multiple source IPs",
                        detail=(
                            f"Credential '{username}:****' was used from "
                            f"{len(distinct_ips)} distinct source IPs "
                            f"within a 1-hour window: "
                            f"{sorted(distinct_ips)}"
                        ),
                        weight=_CHECK_WEIGHTS["LATM-001"],
                        source_ips=sorted(distinct_ips),
                        event_ids=[e.event_id for e in window],
                    )
                )
                break  # one finding per credential pair is sufficient

    return findings


def _check_latm002(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-002: Same source IP accessed >2 distinct honeypot hosts within 30 min."""
    THIRTY_MIN_MS = 30 * 60 * 1000

    # Group events by source_ip
    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)

    findings: List[LATMFinding] = []
    for ip, ip_evs in ip_events.items():
        sorted_evs = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        left = 0
        for right in range(len(sorted_evs)):
            while (
                sorted_evs[right].timestamp_ms - sorted_evs[left].timestamp_ms
                > THIRTY_MIN_MS
            ):
                left += 1
            window = sorted_evs[left : right + 1]
            distinct_hosts = set(e.honeypot_host for e in window)
            if len(distinct_hosts) > 2:
                findings.append(
                    LATMFinding(
                        check_id="LATM-002",
                        severity=_SEVERITY["LATM-002"],
                        title="Sequential honeypot host access from single IP",
                        detail=(
                            f"Source IP {ip} accessed {len(distinct_hosts)} "
                            f"distinct honeypot hosts within a 30-minute window: "
                            f"{sorted(distinct_hosts)}"
                        ),
                        weight=_CHECK_WEIGHTS["LATM-002"],
                        source_ips=[ip],
                        event_ids=[e.event_id for e in window],
                    )
                )
                break  # one finding per IP

    return findings


def _check_latm003(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-003: >5 distinct usernames from same IP within 10 minutes."""
    TEN_MIN_MS = 10 * 60 * 1000

    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        if ev.username is not None:
            ip_events[ev.source_ip].append(ev)

    findings: List[LATMFinding] = []
    for ip, ip_evs in ip_events.items():
        sorted_evs = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        left = 0
        for right in range(len(sorted_evs)):
            while (
                sorted_evs[right].timestamp_ms - sorted_evs[left].timestamp_ms
                > TEN_MIN_MS
            ):
                left += 1
            window = sorted_evs[left : right + 1]
            distinct_users = set(e.username for e in window if e.username is not None)
            if len(distinct_users) > 5:
                findings.append(
                    LATMFinding(
                        check_id="LATM-003",
                        severity=_SEVERITY["LATM-003"],
                        title="Username enumeration detected",
                        detail=(
                            f"Source IP {ip} attempted {len(distinct_users)} "
                            f"distinct usernames within a 10-minute window: "
                            f"{sorted(distinct_users)}"
                        ),
                        weight=_CHECK_WEIGHTS["LATM-003"],
                        source_ips=[ip],
                        event_ids=[e.event_id for e in window],
                    )
                )
                break  # one finding per IP

    return findings


def _check_latm004(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-004: Source IP is RFC1918 or loopback — insider threat / compromised host."""
    internal_ips = sorted(
        {ev.source_ip for ev in events if _is_internal_ip(ev.source_ip)}
    )
    if not internal_ips:
        return []

    involved_event_ids = [
        ev.event_id for ev in events if ev.source_ip in set(internal_ips)
    ]

    return [
        LATMFinding(
            check_id="LATM-004",
            severity=_SEVERITY["LATM-004"],
            title="Internal IP source detected — possible insider threat",
            detail=(
                f"Events originated from {len(internal_ips)} internal "
                f"(RFC1918/loopback) IP(s): {internal_ips}"
            ),
            weight=_CHECK_WEIGHTS["LATM-004"],
            source_ips=internal_ips,
            event_ids=involved_event_ids,
        )
    ]


def _check_latm005(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-005: Successful auth followed within 5 min by attempt to different host."""
    FIVE_MIN_MS = 5 * 60 * 1000

    # Group all events by source_ip (need both success and subsequent events)
    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)

    findings: List[LATMFinding] = []
    for ip, ip_evs in ip_events.items():
        sorted_evs = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        # For each successful event, look for a subsequent event to a different host
        fired = False
        trigger_events: List[HoneypotEvent] = []
        for i, ev in enumerate(sorted_evs):
            if not ev.success:
                continue
            # Look ahead within FIVE_MIN_MS
            for j in range(i + 1, len(sorted_evs)):
                follow = sorted_evs[j]
                if follow.timestamp_ms - ev.timestamp_ms > FIVE_MIN_MS:
                    break
                if follow.honeypot_host != ev.honeypot_host:
                    trigger_events = [ev, follow]
                    fired = True
                    break
            if fired:
                break

        if fired:
            findings.append(
                LATMFinding(
                    check_id="LATM-005",
                    severity=_SEVERITY["LATM-005"],
                    title="Post-authentication lateral pivot detected",
                    detail=(
                        f"Source IP {ip} had a successful authentication on "
                        f"'{trigger_events[0].honeypot_host}' followed within "
                        f"5 minutes by activity on a different host "
                        f"'{trigger_events[1].honeypot_host}'"
                    ),
                    weight=_CHECK_WEIGHTS["LATM-005"],
                    source_ips=[ip],
                    event_ids=[e.event_id for e in trigger_events],
                )
            )

    return findings


def _check_latm006(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-006: Failed attempt after a prior successful auth from same IP."""
    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)

    findings: List[LATMFinding] = []
    for ip, ip_evs in ip_events.items():
        sorted_evs = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        # Find the earliest success
        earliest_success: Optional[HoneypotEvent] = None
        for ev in sorted_evs:
            if ev.success:
                earliest_success = ev
                break
        if earliest_success is None:
            continue
        # Look for any failed event after the earliest success
        failed_after = [
            ev
            for ev in sorted_evs
            if not ev.success and ev.timestamp_ms > earliest_success.timestamp_ms
        ]
        if failed_after:
            findings.append(
                LATMFinding(
                    check_id="LATM-006",
                    severity=_SEVERITY["LATM-006"],
                    title="Post-compromise reconnaissance detected",
                    detail=(
                        f"Source IP {ip} had a prior successful authentication "
                        f"followed by {len(failed_after)} failed attempt(s) — "
                        f"possible post-compromise lateral movement exploration"
                    ),
                    weight=_CHECK_WEIGHTS["LATM-006"],
                    source_ips=[ip],
                    event_ids=[earliest_success.event_id]
                    + [e.event_id for e in failed_after],
                )
            )

    return findings


def _check_latm007(events: List[HoneypotEvent]) -> List[LATMFinding]:
    """LATM-007: >10 events from same source IP within 1 minute (burst/automation)."""
    ONE_MIN_MS = 60 * 1000

    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)

    findings: List[LATMFinding] = []
    for ip, ip_evs in ip_events.items():
        sorted_evs = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        left = 0
        for right in range(len(sorted_evs)):
            while (
                sorted_evs[right].timestamp_ms - sorted_evs[left].timestamp_ms
                > ONE_MIN_MS
            ):
                left += 1
            window = sorted_evs[left : right + 1]
            if len(window) > 10:
                findings.append(
                    LATMFinding(
                        check_id="LATM-007",
                        severity=_SEVERITY["LATM-007"],
                        title="Burst activity — automated tool suspected",
                        detail=(
                            f"Source IP {ip} generated {len(window)} events "
                            f"within a 1-minute window — automation or scripted "
                            f"attack suspected"
                        ),
                        weight=_CHECK_WEIGHTS["LATM-007"],
                        source_ips=[ip],
                        event_ids=[e.event_id for e in window],
                    )
                )
                break  # one finding per IP

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(events: List[HoneypotEvent]) -> LATMResult:
    """Analyze a batch of honeypot events for lateral movement patterns.

    Each of the seven LATM checks is applied independently. Findings are
    collected, the risk score is the sum of weights for unique fired check IDs
    (capped at 100), and a threat level is derived from the risk score.
    """
    all_findings: List[LATMFinding] = []

    # Run all checks in definition order
    all_findings.extend(_check_latm001(events))
    all_findings.extend(_check_latm002(events))
    all_findings.extend(_check_latm003(events))
    all_findings.extend(_check_latm004(events))
    all_findings.extend(_check_latm005(events))
    all_findings.extend(_check_latm006(events))
    all_findings.extend(_check_latm007(events))

    fired_ids = [f.check_id for f in all_findings]
    score = _compute_risk(fired_ids)
    level = _threat_level(score)

    return LATMResult(
        findings=all_findings,
        risk_score=score,
        threat_level=level,
    )


def analyze_stream(
    events: List[HoneypotEvent],
    window_size: int = 1000,
) -> List[LATMResult]:
    """Analyze events in sliding windows of *window_size* events each.

    Windows are non-overlapping slices of the input list. Each slice is passed
    to :func:`analyze` independently. The list is NOT pre-sorted — events are
    processed in the order supplied, matching real-world streaming behaviour.

    Args:
        events:      Full list of honeypot events to analyse.
        window_size: Number of events per analysis window (default 1000).

    Returns:
        One :class:`LATMResult` per window.
    """
    if not events or window_size < 1:
        return []

    results: List[LATMResult] = []
    for start in range(0, len(events), window_size):
        chunk = events[start : start + window_size]
        results.append(analyze(chunk))
    return results
