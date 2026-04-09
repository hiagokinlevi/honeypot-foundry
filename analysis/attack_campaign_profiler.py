"""
attack_campaign_profiler.py
───────────────────────────
Profiles attacker campaigns across multiple honeypot sessions by correlating
events from different IPs, time windows, and attack patterns.

Identifies coordinated campaigns distinct from single isolated incidents by
running seven deterministic checks (CAMP-001 … CAMP-007) and aggregating a
weighted risk score.

Python 3.9 compatible — no walrus operator, no 3.10+ structural pattern match.
"""

from __future__ import annotations

import hashlib
import re
import socket
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HoneypotEvent:
    """A single event recorded by a honeypot sensor."""

    event_id: str
    source_ip: str
    service: str          # "ssh", "http", "redis", "mysql", …
    timestamp_ms: int     # epoch milliseconds

    username: str = ""
    password: str = ""
    user_agent: str = ""  # banner, User-Agent, or session fingerprint
    event_type: str = ""  # "auth_attempt", "probe", "connect", …


@dataclass
class CampaignCheck:
    """A single fired check within a campaign profile."""

    check_id: str
    severity: str         # CRITICAL / HIGH / MEDIUM
    description: str
    evidence: str         # concise human-readable evidence string
    weight: int
    affected_ips: List[str]  # IPs contributing to this finding (≤ 10)


@dataclass
class CampaignProfile:
    """Aggregated profile for a set of honeypot events forming one campaign."""

    campaign_id: str           # 12-char SHA-256 prefix of sorted event IDs
    checks_fired: List[CampaignCheck]
    risk_score: int            # min(100, sum of weights)
    campaign_tier: str         # COORDINATED / LIKELY_COORDINATED / SUSPICIOUS / ISOLATED
    total_events: int
    unique_ips: int
    time_span_seconds: int
    _raw_events: List[HoneypotEvent] = field(default_factory=list, repr=False)

    # ── public helpers ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise the profile to a plain Python dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "risk_score": self.risk_score,
            "campaign_tier": self.campaign_tier,
            "total_events": self.total_events,
            "unique_ips": self.unique_ips,
            "time_span_seconds": self.time_span_seconds,
            "checks_fired": [
                {
                    "check_id": c.check_id,
                    "severity": c.severity,
                    "description": c.description,
                    "evidence": c.evidence,
                    "weight": c.weight,
                    "affected_ips": c.affected_ips,
                }
                for c in self.checks_fired
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary string."""
        checks_str = ", ".join(c.check_id for c in self.checks_fired) or "none"
        return (
            f"[{self.campaign_id}] tier={self.campaign_tier} "
            f"score={self.risk_score} events={self.total_events} "
            f"ips={self.unique_ips} span={self.time_span_seconds}s "
            f"checks={checks_str}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _campaign_id(events: List[HoneypotEvent]) -> str:
    """Deterministic 12-char hex ID from sorted unique event IDs."""
    joined = ",".join(sorted(set(e.event_id for e in events)))
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def _tier(score: int) -> str:
    """Map numeric risk score to campaign tier string."""
    if score >= 60:
        return "COORDINATED"
    if score >= 35:
        return "LIKELY_COORDINATED"
    if score >= 15:
        return "SUSPICIOUS"
    return "ISOLATED"


def _ip_to_int(ip: str) -> Optional[int]:
    """Convert dotted-decimal IPv4 to integer; return None on failure."""
    try:
        packed = socket.inet_aton(ip)
        return struct.unpack("!I", packed)[0]
    except (OSError, struct.error):
        return None


def _slash24_key(ip: str) -> Optional[str]:
    """Return the first three octets joined by '.' (the /24 network key)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3])


def _slash28_key(ip: str) -> Optional[int]:
    """Return the /28 network integer for an IP (mask off last 4 bits)."""
    val = _ip_to_int(ip)
    if val is None:
        return None
    return val & 0xFFFFFFF0   # /28 → keep top 28 bits


def _cap_ips(ips: List[str]) -> List[str]:
    """Return up to 10 IPs, sorted for determinism."""
    return sorted(set(ips))[:10]


# ──────────────────────────────────────────────────────────────────────────────
# Individual check implementations
# ──────────────────────────────────────────────────────────────────────────────

def _check_camp001(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-001: Multi-source credential reuse.
    Same (username, password) pair seen from ≥3 distinct source IPs.
    """
    cred_ips: Dict[Tuple[str, str], set] = defaultdict(set)
    for ev in events:
        if ev.username and ev.password:
            cred_ips[(ev.username, ev.password)].add(ev.source_ip)

    # Find pair with most unique IPs
    best: Optional[Tuple[Tuple[str, str], set]] = None
    for pair, ips in cred_ips.items():
        if len(ips) >= 3:
            if best is None or len(ips) > len(best[1]):
                best = (pair, ips)

    if best is None:
        return None

    pair, ips = best
    return CampaignCheck(
        check_id="CAMP-001",
        severity="CRITICAL",
        description="Multi-source credential reuse",
        evidence=(
            f"Credential pair '{pair[0]}'/'{pair[1]}' "
            f"reused from {len(ips)} distinct IPs"
        ),
        weight=45,
        affected_ips=_cap_ips(list(ips)),
    )


def _check_camp002(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-002: Distributed scanning.
    ≥5 distinct IPs targeting the same service within any 3600-second window.
    """
    # Group events by service, sorted by timestamp
    service_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        if ev.service:
            service_events[ev.service].append(ev)

    best_service: Optional[str] = None
    best_ips: List[str] = []

    for service, sevs in service_events.items():
        sevs_sorted = sorted(sevs, key=lambda e: e.timestamp_ms)
        ts = [e.timestamp_ms for e in sevs_sorted]
        n = len(ts)
        left = 0
        window_ips: set = set()

        for right in range(n):
            window_ips.add(sevs_sorted[right].source_ip)
            # Shrink left until window fits within 3600 seconds
            while ts[right] - ts[left] > 3_600_000:
                # Remove left IP only if no other event in window uses it
                removed_ip = sevs_sorted[left].source_ip
                left += 1
                # Recompute IPs in [left, right] only when needed
                window_ips = {sevs_sorted[i].source_ip for i in range(left, right + 1)}

            if len(window_ips) >= 5:
                if len(window_ips) > len(best_ips):
                    best_service = service
                    best_ips = list(window_ips)

    if not best_ips:
        return None

    return CampaignCheck(
        check_id="CAMP-002",
        severity="HIGH",
        description="Distributed scanning",
        evidence=(
            f"Service '{best_service}' targeted by {len(best_ips)} "
            f"distinct IPs within a 1-hour window"
        ),
        weight=30,
        affected_ips=_cap_ips(best_ips),
    )


def _check_camp003(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-003: Sequential subnet sweep.
    IPs in a /24 subnet appearing in sorted last-octet order with
    <5 minutes (300 s) between each consecutive new IP.
    """
    # Build per-/24-subnet map: last_octet -> first-seen timestamp_ms
    subnet_first_seen: Dict[str, Dict[int, int]] = defaultdict(dict)

    for ev in events:
        key = _slash24_key(ev.source_ip)
        if key is None:
            continue
        try:
            last_octet = int(ev.source_ip.split(".")[-1])
        except ValueError:
            continue
        parts = ev.source_ip.split(".")
        if len(parts) != 4:
            continue
        # Record the minimum timestamp for this (subnet, last_octet) pair
        if last_octet not in subnet_first_seen[key]:
            subnet_first_seen[key][last_octet] = ev.timestamp_ms
        else:
            if ev.timestamp_ms < subnet_first_seen[key][last_octet]:
                subnet_first_seen[key][last_octet] = ev.timestamp_ms

    # For each /24, sort last octets and look for 3 consecutive within 300 s each
    for subnet_key, octet_ts in subnet_first_seen.items():
        if len(octet_ts) < 3:
            continue
        sorted_octets = sorted(octet_ts.keys())
        # Slide a window of 3 consecutive sorted octets
        for i in range(len(sorted_octets) - 2):
            a, b, c = sorted_octets[i], sorted_octets[i + 1], sorted_octets[i + 2]
            ts_a = octet_ts[a]
            ts_b = octet_ts[b]
            ts_c = octet_ts[c]
            # Each consecutive pair must appear within 300 s of the previous
            gap_ab = abs(ts_b - ts_a)
            gap_bc = abs(ts_c - ts_b)
            if gap_ab < 300_000 and gap_bc < 300_000:
                ips = [
                    f"{subnet_key}.{a}",
                    f"{subnet_key}.{b}",
                    f"{subnet_key}.{c}",
                ]
                return CampaignCheck(
                    check_id="CAMP-003",
                    severity="HIGH",
                    description="Sequential subnet sweep",
                    evidence=(
                        f"Sequential IPs in /{subnet_key}.x (/24): "
                        f"{ips[0]} -> {ips[1]} -> {ips[2]} "
                        f"with gaps {gap_ab // 1000}s, {gap_bc // 1000}s"
                    ),
                    weight=25,
                    affected_ips=_cap_ips(ips),
                )

    return None


def _check_camp004(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-004: Tool fingerprint clustering.
    Same user_agent (non-empty) seen from ≥3 distinct IPs.
    """
    ua_ips: Dict[str, set] = defaultdict(set)
    for ev in events:
        if ev.user_agent.strip():
            ua_ips[ev.user_agent].add(ev.source_ip)

    best_ua: Optional[str] = None
    best_ips: set = set()
    for ua, ips in ua_ips.items():
        if len(ips) >= 3 and len(ips) > len(best_ips):
            best_ua = ua
            best_ips = ips

    if best_ua is None:
        return None

    return CampaignCheck(
        check_id="CAMP-004",
        severity="HIGH",
        description="Tool fingerprint clustering",
        evidence=(
            f"User-Agent/fingerprint '{best_ua[:60]}' "
            f"seen from {len(best_ips)} distinct IPs"
        ),
        weight=25,
        affected_ips=_cap_ips(list(best_ips)),
    )


def _check_camp005(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-005: Temporal burst pattern.
    ≥20 events across ≥3 IPs within any 300-second window,
    followed by silence (no events) for ≥1800 seconds after the window end.

    Strategy: for each candidate RIGHT boundary index, find the sliding-window
    of events in [ts[right]-300_000, ts[right]].  Check density/IP criteria.
    Then verify silence: the event immediately AFTER ts[right] (if any) must be
    ≥1800 s later.  This ensures the silence is measured from the actual last
    event of the burst, not from an arbitrary 300-s cutoff.
    """
    if not events:
        return None

    sorted_events = sorted(events, key=lambda e: e.timestamp_ms)
    ts = [e.timestamp_ms for e in sorted_events]
    n = len(ts)

    # Maintain a sliding left pointer for the 300-second window
    left = 0
    for right in range(n):
        # Advance left so window spans at most 300 seconds
        while ts[right] - ts[left] > 300_000:
            left += 1

        window_evs = sorted_events[left:right + 1]
        if len(window_evs) < 20:
            continue

        window_ips = {e.source_ip for e in window_evs}
        if len(window_ips) < 3:
            continue

        # Silence check: first event strictly after this window's right boundary
        first_after_idx = right + 1
        if first_after_idx >= n:
            # No events after the window — dataset ends here; silence confirmed
            return CampaignCheck(
                check_id="CAMP-005",
                severity="MEDIUM",
                description="Temporal burst pattern",
                evidence=(
                    f"{len(window_evs)} events from {len(window_ips)} IPs "
                    f"within a 5-minute burst window, followed by ≥30 min silence"
                ),
                weight=20,
                affected_ips=_cap_ips(list(window_ips)),
            )

        gap_ms = ts[first_after_idx] - ts[right]
        if gap_ms >= 1_800_000:
            return CampaignCheck(
                check_id="CAMP-005",
                severity="MEDIUM",
                description="Temporal burst pattern",
                evidence=(
                    f"{len(window_evs)} events from {len(window_ips)} IPs "
                    f"within a 5-minute burst window, followed by ≥30 min silence"
                ),
                weight=20,
                affected_ips=_cap_ips(list(window_ips)),
            )
        # Gap too small — continue scanning with right advancing

    return None


# Password classification helpers for CAMP-006
_COMMON_WORD_RE = re.compile(r"^[a-z]{1,8}$")
_TARGETED_RE = re.compile(r"(20\d{2}|@)")


def _is_common_word_password(pw: str) -> bool:
    """True if password matches the 'common word' pattern: all lowercase, len ≤ 8, no digits."""
    return bool(_COMMON_WORD_RE.match(pw))


def _is_targeted_password(pw: str) -> bool:
    """True if password contains a year (20xx) or '@' symbol."""
    return bool(_TARGETED_RE.search(pw))


def _check_camp006(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-006: Credential progression.
    Same IP uses common-word passwords in early sessions and targeted passwords
    (containing year 20xx or '@') in later sessions.
    """
    # Group by source_ip, sort by timestamp
    ip_events: Dict[str, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        if ev.password:
            ip_events[ev.source_ip].append(ev)

    matching_ips: List[str] = []

    for ip, ip_evs in ip_events.items():
        ip_evs_sorted = sorted(ip_evs, key=lambda e: e.timestamp_ms)
        passwords = [e.password for e in ip_evs_sorted]
        if len(passwords) < 2:
            continue

        # Split into early (first half) and late (second half)
        mid = len(passwords) // 2
        early_pws = passwords[:mid]
        late_pws = passwords[mid:]

        early_common = any(_is_common_word_password(p) for p in early_pws)
        late_targeted = any(_is_targeted_password(p) for p in late_pws)

        if early_common and late_targeted:
            matching_ips.append(ip)

    if not matching_ips:
        return None

    return CampaignCheck(
        check_id="CAMP-006",
        severity="MEDIUM",
        description="Credential progression",
        evidence=(
            f"{len(matching_ips)} IP(s) progressed from generic passwords "
            f"to targeted credential patterns"
        ),
        weight=20,
        affected_ips=_cap_ips(matching_ips),
    )


def _check_camp007(events: List[HoneypotEvent]) -> Optional[CampaignCheck]:
    """
    CAMP-007: Return attacker.
    Same IP (or /28 subnet) seen in events ≥48 hours apart.
    """
    # Per-IP span
    ip_min_ts: Dict[str, int] = {}
    ip_max_ts: Dict[str, int] = {}

    for ev in events:
        ip = ev.source_ip
        ts = ev.timestamp_ms
        if ip not in ip_min_ts:
            ip_min_ts[ip] = ts
            ip_max_ts[ip] = ts
        else:
            if ts < ip_min_ts[ip]:
                ip_min_ts[ip] = ts
            if ts > ip_max_ts[ip]:
                ip_max_ts[ip] = ts

    returning_ips: List[str] = []
    for ip in ip_min_ts:
        if ip_max_ts[ip] - ip_min_ts[ip] > 172_800_000:  # > 48 h in ms
            returning_ips.append(ip)

    if returning_ips:
        return CampaignCheck(
            check_id="CAMP-007",
            severity="MEDIUM",
            description="Return attacker",
            evidence=(
                f"{len(returning_ips)} IP(s) returned after >48 h gap"
            ),
            weight=15,
            affected_ips=_cap_ips(returning_ips),
        )

    # /28 subnet grouping fallback
    subnet28_min: Dict[int, int] = {}
    subnet28_max: Dict[int, int] = {}
    subnet28_ips: Dict[int, set] = defaultdict(set)

    for ev in events:
        key = _slash28_key(ev.source_ip)
        if key is None:
            continue
        ts = ev.timestamp_ms
        subnet28_ips[key].add(ev.source_ip)
        if key not in subnet28_min:
            subnet28_min[key] = ts
            subnet28_max[key] = ts
        else:
            if ts < subnet28_min[key]:
                subnet28_min[key] = ts
            if ts > subnet28_max[key]:
                subnet28_max[key] = ts

    for key in subnet28_min:
        if (
            subnet28_max[key] - subnet28_min[key] > 172_800_000
            and len(subnet28_ips[key]) >= 2
        ):
            ips = list(subnet28_ips[key])
            return CampaignCheck(
                check_id="CAMP-007",
                severity="MEDIUM",
                description="Return attacker",
                evidence=(
                    f"/28 subnet group ({len(ips)} IPs) "
                    f"returned after >48 h gap"
                ),
                weight=15,
                affected_ips=_cap_ips(ips),
            )

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def profile_campaign(events: List[HoneypotEvent]) -> CampaignProfile:
    """
    Profile a single campaign from a flat list of HoneypotEvents.

    All events are treated as one campaign.  Runs CAMP-001 … CAMP-007 and
    returns a CampaignProfile with risk score and tier.
    """
    if not events:
        return CampaignProfile(
            campaign_id="000000000000",
            checks_fired=[],
            risk_score=0,
            campaign_tier="ISOLATED",
            total_events=0,
            unique_ips=0,
            time_span_seconds=0,
            _raw_events=[],
        )

    checks_fired: List[CampaignCheck] = []

    for checker in (
        _check_camp001,
        _check_camp002,
        _check_camp003,
        _check_camp004,
        _check_camp005,
        _check_camp006,
        _check_camp007,
    ):
        result = checker(events)
        if result is not None:
            checks_fired.append(result)

    raw_score = sum(c.weight for c in checks_fired)
    risk_score = min(100, raw_score)

    all_ts = [e.timestamp_ms for e in events]
    time_span_seconds = (max(all_ts) - min(all_ts)) // 1000

    return CampaignProfile(
        campaign_id=_campaign_id(events),
        checks_fired=checks_fired,
        risk_score=risk_score,
        campaign_tier=_tier(risk_score),
        total_events=len(events),
        unique_ips=len({e.source_ip for e in events}),
        time_span_seconds=time_span_seconds,
        _raw_events=list(events),
    )


def profile_campaigns_by_window(
    events: List[HoneypotEvent],
    window_seconds: int = 3600,
) -> List[CampaignProfile]:
    """
    Split events into non-overlapping time windows of *window_seconds* and
    profile each group independently.

    Windows are anchored to the earliest event's timestamp rounded down to
    the window boundary.  Empty windows produce no profile.  Returns profiles
    sorted by the window start time (ascending).
    """
    if not events:
        return []

    window_ms = window_seconds * 1000
    min_ts = min(e.timestamp_ms for e in events)
    # Anchor: epoch origin so windows align consistently
    origin = min_ts - (min_ts % window_ms)

    buckets: Dict[int, List[HoneypotEvent]] = defaultdict(list)
    for ev in events:
        bucket_index = (ev.timestamp_ms - origin) // window_ms
        buckets[bucket_index].append(ev)

    profiles: List[CampaignProfile] = []
    for idx in sorted(buckets.keys()):
        bucket_events = buckets[idx]
        if bucket_events:
            profiles.append(profile_campaign(bucket_events))

    return profiles
