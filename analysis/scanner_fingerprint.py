"""
Behavioral Scanner Fingerprinting
====================================
Classifies attacker tool types from observed honeypot event patterns —
connection timing, credential sets, User-Agent strings, probe sequences,
and port combinations — to distinguish automated scanners from human
operators and identify specific tools.

Scanner Categories
-------------------
SHODAN        — Well-known internet scanner with distinctive probe timing and
                specific banner-grab patterns on standard ports.
MASSCAN       — High-speed port scanner with sub-second timing, minimal banner
                exchange, and large batches of SYN-only probes.
ZGRAB         — Go-based banner grabber; probes specific application protocols
                with structured payloads.
METASPLOIT    — Framework-style scanner with characteristic module prefixes,
                payload strings, and staged connection patterns.
CREDENTIAL_STUFFING_BOT — Automated credential replayer with consistent
                timing intervals and pre-built username:password pairs.
CUSTOM_SCRIPT — Low-sophistication custom script: irregular timing, common
                default credentials, single-threaded patterns.
HUMAN         — Manual operator: irregular timing > 1 second between actions,
                exploration-style probe sequence, varied credentials.
UNKNOWN       — Insufficient data to classify.

Usage::

    from analysis.scanner_fingerprint import ScannerFingerprinter

    fp = ScannerFingerprinter()
    for event in events:
        fp.ingest(event)
    results = fp.fingerprint_all()
    for ip, result in results.items():
        print(result.summary())
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScannerType(str, Enum):
    SHODAN                 = "SHODAN"
    MASSCAN                = "MASSCAN"
    ZGRAB                  = "ZGRAB"
    METASPLOIT             = "METASPLOIT"
    CREDENTIAL_STUFFING_BOT = "CREDENTIAL_STUFFING_BOT"
    CUSTOM_SCRIPT          = "CUSTOM_SCRIPT"
    HUMAN                  = "HUMAN"
    UNKNOWN                = "UNKNOWN"


class FingerprintConfidence(str, Enum):
    HIGH   = "HIGH"    # score >= 0.75
    MEDIUM = "MEDIUM"  # score >= 0.45
    LOW    = "LOW"     # score < 0.45


# ---------------------------------------------------------------------------
# Fingerprint signal sets
# ---------------------------------------------------------------------------

# Known Shodan User-Agent fragments and HTTP headers
_SHODAN_UA_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"shodan",
        r"shodan\.io",
        r"Mozilla/5\.0 \(compatible; ShodanBot",
    ]
]

# Masscan-specific characteristics (very fast, minimal exchange)
_MASSCAN_UA_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"masscan",
        r"masscan/\d+",
    ]
]

# ZGrab-specific characteristics
_ZGRAB_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"zgrab",
        r"zgrab/\d+",
        r"ZGrab",
    ]
]

# Metasploit-related signatures in credentials and payloads
_METASPLOIT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"metasploit",
        r"msfconsole",
        r"msf\d*>",
        r"meterpreter",
        r"payload/",
        r"exploit/",
        r"auxiliary/scanner",
        r"\bmsf\b",
    ]
]

# Known default credential sets used by scanner bots
_BOT_CREDENTIAL_SETS: set[tuple[str, str]] = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("admin", ""),
    ("", ""),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("support", "support"),
}

# Ports typically probed by specific scanners
_SHODAN_PROBE_PORTS: set[int] = {21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443}
_MASSCAN_PROBE_PORTS: set[int] = {22, 80, 443, 8080}  # mass-probed ports

# Timing thresholds
_INTER_EVENT_FAST_S   = 0.5    # < 0.5s between events → automated (masscan-style)
_INTER_EVENT_BOT_S    = 2.0    # < 2s → bot/script
_INTER_EVENT_HUMAN_S  = 5.0    # > 5s average → human


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FingerprintResult:
    """
    The scanner classification result for a single source IP.

    Attributes:
        source_ip:     IP address classified.
        scanner_type:  Most likely scanner type.
        confidence:    Confidence bucket.
        score:         Aggregate classification score 0.0–1.0.
        signals:       List of human-readable signal descriptions.
        event_count:   Total events analysed.
        unique_usernames: Distinct usernames observed.
        unique_passwords: Distinct passwords observed.
        ports_probed:  Set of destination ports probed.
        avg_inter_event_s: Average time between events (None if < 2 events).
    """
    source_ip:         str
    scanner_type:      ScannerType = ScannerType.UNKNOWN
    confidence:        FingerprintConfidence = FingerprintConfidence.LOW
    score:             float = 0.0
    signals:           list[str] = field(default_factory=list)
    event_count:       int = 0
    unique_usernames:  set[str] = field(default_factory=set)
    unique_passwords:  set[str] = field(default_factory=set)
    ports_probed:      set[int] = field(default_factory=set)
    avg_inter_event_s: Optional[float] = None

    def summary(self) -> str:
        conf_str = f"confidence={self.confidence.value}"
        timing   = (
            f"avg_gap={self.avg_inter_event_s:.2f}s"
            if self.avg_inter_event_s is not None
            else "timing=n/a"
        )
        return (
            f"[{self.scanner_type.value}] {self.source_ip} | "
            f"{conf_str} score={self.score:.2f} | "
            f"{self.event_count} events {timing} | "
            f"signals=[{'; '.join(self.signals[:3])}]"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip":         self.source_ip,
            "scanner_type":      self.scanner_type.value,
            "confidence":        self.confidence.value,
            "score":             round(self.score, 3),
            "signals":           self.signals,
            "event_count":       self.event_count,
            "unique_usernames":  sorted(self.unique_usernames),
            "unique_passwords":  sorted(self.unique_passwords),
            "ports_probed":      sorted(self.ports_probed),
            "avg_inter_event_s": (
                round(self.avg_inter_event_s, 3)
                if self.avg_inter_event_s is not None else None
            ),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_str(event: dict[str, Any], *keys: str) -> str:
    for key in keys:
        val = event.get(key)
        if val and isinstance(val, str):
            return val.strip()
    return ""


def _get_int(event: dict[str, Any], *keys: str) -> Optional[int]:
    for key in keys:
        val = event.get(key)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                continue
    return None


def _parse_ts(event: dict[str, Any]) -> Optional[float]:
    """Return Unix timestamp from event, or None."""
    for key in ("timestamp", "ts", "time", "event_time"):
        raw = event.get(key)
        if not raw:
            continue
        if isinstance(raw, (int, float)):
            return float(raw)
        if isinstance(raw, str):
            try:
                dt = datetime.fromisoformat(raw.rstrip("Z"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
    return None


def _match_any(patterns: list[re.Pattern[str]], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _compute_inter_event_gaps(timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    sorted_ts = sorted(timestamps)
    return [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]


# ---------------------------------------------------------------------------
# ScannerFingerprinter
# ---------------------------------------------------------------------------

class ScannerFingerprinter:
    """
    Classifies source IPs by scanner tool type from observed honeypot events.

    Ingests raw event dicts and fingerprints each distinct source IP.

    Args:
        min_events: Minimum events required to classify an IP.
                    IPs with fewer events get UNKNOWN / LOW confidence.
    """

    def __init__(self, min_events: int = 2) -> None:
        self._min_events = min_events
        self._events: list[dict[str, Any]] = []

    def ingest(self, event: dict[str, Any]) -> None:
        """Add a single event."""
        self._events.append(event)

    def ingest_batch(self, events: list[dict[str, Any]]) -> int:
        """Add multiple events. Returns count added."""
        self._events.extend(events)
        return len(events)

    def clear(self) -> None:
        """Remove all ingested events."""
        self._events.clear()

    @property
    def event_count(self) -> int:
        return len(self._events)

    def fingerprint_ip(self, source_ip: str) -> FingerprintResult:
        """
        Classify a single source IP based on its observed events.
        """
        ip_events = [
            e for e in self._events
            if _get_str(e, "source_ip", "src_ip", "ip") == source_ip
        ]
        return self._classify(source_ip, ip_events)

    def fingerprint_all(self) -> dict[str, FingerprintResult]:
        """
        Classify all source IPs observed in ingested events.

        Returns a dict of IP → FingerprintResult.
        """
        by_ip: dict[str, list[dict[str, Any]]] = {}
        for event in self._events:
            ip = _get_str(event, "source_ip", "src_ip", "ip")
            if not ip:
                continue
            by_ip.setdefault(ip, []).append(event)

        return {ip: self._classify(ip, events) for ip, events in by_ip.items()}

    # ------------------------------------------------------------------
    # Classification engine
    # ------------------------------------------------------------------

    def _classify(
        self,
        source_ip: str,
        events: list[dict[str, Any]],
    ) -> FingerprintResult:
        result = FingerprintResult(
            source_ip=source_ip,
            event_count=len(events),
        )

        if not events:
            return result

        # Aggregate signals from events
        usernames: set[str] = set()
        passwords: set[str] = set()
        ports: set[int] = set()
        user_agents: list[str] = []
        payloads: list[str] = []
        timestamps: list[float] = []

        for event in events:
            if u := _get_str(event, "username", "user", "login"):
                usernames.add(u)
            if p := _get_str(event, "password", "credential", "pw"):
                passwords.add(p)
            if port := _get_int(event, "port", "dest_port", "dport"):
                ports.add(port)
            if ua := _get_str(event, "user_agent", "useragent", "http_user_agent"):
                user_agents.append(ua)
            if payload := _get_str(event, "payload", "data", "raw"):
                payloads.append(payload)
            if ts := _parse_ts(event):
                timestamps.append(ts)

        result.unique_usernames = usernames
        result.unique_passwords = passwords
        result.ports_probed     = ports

        # Compute inter-event timing
        gaps = _compute_inter_event_gaps(timestamps)
        if gaps:
            result.avg_inter_event_s = statistics.mean(gaps)

        # Score each scanner type
        scores: dict[ScannerType, float] = {}
        signals: list[str] = []

        # -- SHODAN --
        shodan_score = 0.0
        ua_blob = " ".join(user_agents)
        if _match_any(_SHODAN_UA_PATTERNS, ua_blob):
            shodan_score += 0.80
            signals.append("Shodan User-Agent detected")
        if ports and ports <= _SHODAN_PROBE_PORTS:
            shodan_score += 0.20
            signals.append(f"Ports match Shodan probe set: {sorted(ports)}")
        scores[ScannerType.SHODAN] = shodan_score

        # -- MASSCAN --
        masscan_score = 0.0
        if _match_any(_MASSCAN_UA_PATTERNS, ua_blob):
            masscan_score += 0.80
            signals.append("Masscan User-Agent detected")
        if gaps and statistics.mean(gaps) < _INTER_EVENT_FAST_S:
            masscan_score += 0.40
            signals.append(f"Ultra-fast timing (avg {statistics.mean(gaps):.3f}s) consistent with masscan")
        if len(events) >= 10 and not usernames:
            # Masscan doesn't do auth — probes only
            masscan_score += 0.20
            signals.append("High probe volume with no credentials — port scan pattern")
        scores[ScannerType.MASSCAN] = masscan_score

        # -- ZGRAB --
        zgrab_score = 0.0
        all_text = " ".join(user_agents + payloads)
        if _match_any(_ZGRAB_PATTERNS, all_text):
            zgrab_score += 0.90
            signals.append("ZGrab signature detected in UA or payload")
        scores[ScannerType.ZGRAB] = zgrab_score

        # -- METASPLOIT --
        msf_score = 0.0
        all_text2 = " ".join(payloads + [
            _get_str(e, "username") for e in events
        ])
        if _match_any(_METASPLOIT_PATTERNS, all_text2):
            msf_score += 0.85
            signals.append("Metasploit signature in payload or credentials")
        scores[ScannerType.METASPLOIT] = msf_score

        # -- CREDENTIAL STUFFING BOT --
        bot_score = 0.0
        cred_pairs = {(u, p) for u, p in zip(
            [_get_str(e, "username") for e in events],
            [_get_str(e, "password", "credential") for e in events],
        ) if u or p}
        bot_matches = cred_pairs & _BOT_CREDENTIAL_SETS
        if bot_matches:
            bot_score += min(0.70, 0.15 * len(bot_matches))
            signals.append(
                f"{len(bot_matches)} known bot credential pair(s): "
                f"{list(bot_matches)[:3]}"
            )
        if gaps and _INTER_EVENT_FAST_S < statistics.mean(gaps) < _INTER_EVENT_BOT_S:
            bot_score += 0.25
            signals.append(f"Bot-speed timing (avg {statistics.mean(gaps):.2f}s)")
        scores[ScannerType.CREDENTIAL_STUFFING_BOT] = bot_score

        # -- CUSTOM SCRIPT --
        script_score = 0.0
        if gaps and _INTER_EVENT_BOT_S <= statistics.mean(gaps) < _INTER_EVENT_HUMAN_S:
            script_score += 0.40
            signals.append(f"Script-speed timing (avg {statistics.mean(gaps):.2f}s)")
        if usernames and len(usernames) <= 3 and len(events) >= 5:
            script_score += 0.30
            signals.append(f"Low username diversity ({len(usernames)}) with high volume")
        scores[ScannerType.CUSTOM_SCRIPT] = script_score

        # -- HUMAN --
        human_score = 0.0
        if gaps and statistics.mean(gaps) >= _INTER_EVENT_HUMAN_S:
            human_score += 0.60
            signals.append(f"Human-speed timing (avg {statistics.mean(gaps):.2f}s)")
        if len(events) <= 5:
            human_score += 0.20
            signals.append("Low event count consistent with manual exploration")
        scores[ScannerType.HUMAN] = human_score

        # Select winner
        if len(events) < self._min_events:
            result.scanner_type = ScannerType.UNKNOWN
            result.score        = 0.0
            result.confidence   = FingerprintConfidence.LOW
            result.signals      = signals
            return result

        best_type  = max(scores, key=lambda k: scores[k])
        best_score = scores[best_type]

        if best_score < 0.10:
            result.scanner_type = ScannerType.UNKNOWN
        else:
            result.scanner_type = best_type

        result.score = min(1.0, best_score)
        result.confidence = (
            FingerprintConfidence.HIGH   if best_score >= 0.75 else
            FingerprintConfidence.MEDIUM if best_score >= 0.45 else
            FingerprintConfidence.LOW
        )
        result.signals = signals
        return result
