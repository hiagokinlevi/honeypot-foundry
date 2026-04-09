"""
SSH Credential Attempt Analyzer
=================================
Aggregates and analyzes credential attempt patterns from the SSH observation
server. All analysis operates on already-masked credential data — raw
credentials are never stored, processed, or logged by this module.

Analysis produced:
  - Top-N attacked usernames (frequency ranking)
  - Top-N credential hashes (same password attempted across IPs — stuffing)
  - Attacks per source IP (sorted by attempt count)
  - Credential-spray detection: same hash_prefix targeting many usernames
  - Credential-stuffing detection: same hash_prefix from many source IPs
  - Temporal attack burst detection: >N attempts in a rolling time window

Usage:
    from honeypots.ssh.credential_logger import CredentialLogger
    from honeypots.common.event import HoneypotEvent

    logger = CredentialLogger()
    logger.record(event)          # Call from the event_callback
    summary = logger.summary()    # Get aggregated statistics
    logger.export_json(path)      # Write summary to disk
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from honeypots.common.event import HoneypotEvent


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Regex to extract the hash_prefix from a masked credential string
# e.g. "[masked:len=8,hash_prefix=abc12345]" → "abc12345"
_HASH_PREFIX_RE = re.compile(r"hash_prefix=([0-9a-f]{8})")

# Minimum number of distinct targets to flag credential-spray
_SPRAY_DISTINCT_USERNAMES_THRESHOLD = 5

# Minimum number of distinct source IPs to flag credential-stuffing
_STUFFING_DISTINCT_IPS_THRESHOLD = 5

# Rolling window for burst detection
_BURST_WINDOW_SECONDS = 60
_BURST_THRESHOLD_EVENTS = 10


def _extract_hash_prefix(masked_credential: str) -> Optional[str]:
    """Extract the hash_prefix from a masked credential value."""
    if not masked_credential:
        return None
    match = _HASH_PREFIX_RE.search(masked_credential)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Attack pattern flags
# ---------------------------------------------------------------------------

@dataclass
class AttackPattern:
    """A detected attack pattern with supporting evidence."""

    pattern_type: str   # "credential_spray", "credential_stuffing", "burst", "brute_force"
    severity: str       # "critical", "high", "medium", "low"
    description: str
    evidence: dict      # Supporting counts/values (no raw credentials)


# ---------------------------------------------------------------------------
# Main logger
# ---------------------------------------------------------------------------

class CredentialLogger:
    """
    Aggregates SSH honeypot credential attempt events and detects attack patterns.

    Thread safety: this class is NOT thread-safe. If used from an asyncio
    context, wrap access in a lock or call from a single task.

    All data stored is either:
      - Metadata (IP, port, timestamp, username)
      - Masked credentials (hash_prefix + length — NOT recoverable)
    Raw credential values are NEVER stored.
    """

    def __init__(self, top_n: int = 20) -> None:
        """
        Args:
            top_n: Maximum number of entries in ranked lists (top usernames, etc.)
        """
        self._top_n = top_n

        # Counters and indexes — no raw credentials stored
        self._total_attempts: int = 0
        self._username_counter: Counter = Counter()
        self._hash_prefix_counter: Counter = Counter()
        self._ip_counter: Counter = Counter()

        # hash_prefix → set of distinct usernames targeted (spray detection)
        self._hash_to_usernames: defaultdict[str, set] = defaultdict(set)

        # hash_prefix → set of distinct source IPs that used it (stuffing detection)
        self._hash_to_ips: defaultdict[str, set] = defaultdict(set)

        # IP → list of timestamps (burst detection)
        self._ip_to_timestamps: defaultdict[str, list] = defaultdict(list)

        # Chronological event timestamps for overall activity tracking
        self._event_timestamps: list[datetime] = []

        # First and last event times
        self._first_event_at: Optional[datetime] = None
        self._last_event_at: Optional[datetime] = None

    def record(self, event: HoneypotEvent) -> None:
        """
        Record a single SSH credential attempt event.

        The event must come from the SSH observation server and must have
        already been processed by HoneypotEvent's masking validator.
        Raw credentials are NEVER accessible through this method.

        Args:
            event: A HoneypotEvent with masked credential_observed.
        """
        self._total_attempts += 1
        ts = event.timestamp

        # Track time bounds
        if self._first_event_at is None or ts < self._first_event_at:
            self._first_event_at = ts
        if self._last_event_at is None or ts > self._last_event_at:
            self._last_event_at = ts
        self._event_timestamps.append(ts)

        source_ip = event.source_ip

        # Count username attempts
        if event.username:
            self._username_counter[event.username] += 1

        # Count IP attempts and record timestamp for burst detection
        self._ip_counter[source_ip] += 1
        self._ip_to_timestamps[source_ip].append(ts)

        # Analyze credential hash patterns (spray/stuffing)
        hash_prefix = _extract_hash_prefix(event.credential_observed or "")
        if hash_prefix:
            self._hash_prefix_counter[hash_prefix] += 1
            if event.username:
                self._hash_to_usernames[hash_prefix].add(event.username)
            self._hash_to_ips[hash_prefix].add(source_ip)

    # -----------------------------------------------------------------------
    # Pattern detection
    # -----------------------------------------------------------------------

    def detect_patterns(self) -> list[AttackPattern]:
        """
        Analyze recorded events and return detected attack patterns.

        Patterns detected:
          - credential_spray:    Same password hash targeting many usernames
          - credential_stuffing: Same password hash from many source IPs
          - burst:               IP exceeding _BURST_THRESHOLD_EVENTS in 60s
          - brute_force:         Single IP with high attempt count

        Returns:
            List of AttackPattern objects, sorted by severity (critical first).
        """
        patterns: list[AttackPattern] = []

        # --- Credential spray (one password → many usernames) ---
        for hp, usernames in self._hash_to_usernames.items():
            if len(usernames) >= _SPRAY_DISTINCT_USERNAMES_THRESHOLD:
                patterns.append(AttackPattern(
                    pattern_type="credential_spray",
                    severity="high",
                    description=(
                        f"A single credential hash_prefix '{hp}' was used against "
                        f"{len(usernames)} distinct usernames — password spray pattern"
                    ),
                    evidence={
                        "hash_prefix": hp,
                        "distinct_usernames_targeted": len(usernames),
                        "total_attempts": self._hash_prefix_counter[hp],
                    },
                ))

        # --- Credential stuffing (one password from many IPs) ---
        for hp, ips in self._hash_to_ips.items():
            if len(ips) >= _STUFFING_DISTINCT_IPS_THRESHOLD:
                patterns.append(AttackPattern(
                    pattern_type="credential_stuffing",
                    severity="high",
                    description=(
                        f"A single credential hash_prefix '{hp}' was observed from "
                        f"{len(ips)} distinct IPs — coordinated stuffing pattern"
                    ),
                    evidence={
                        "hash_prefix": hp,
                        "distinct_source_ips": len(ips),
                        "total_attempts": self._hash_prefix_counter[hp],
                    },
                ))

        # --- Burst detection (many attempts from one IP in short window) ---
        window = timedelta(seconds=_BURST_WINDOW_SECONDS)
        for ip, timestamps in self._ip_to_timestamps.items():
            sorted_ts = sorted(timestamps)
            for i, start_ts in enumerate(sorted_ts):
                end_ts = start_ts + window
                count_in_window = sum(1 for t in sorted_ts[i:] if t <= end_ts)
                if count_in_window >= _BURST_THRESHOLD_EVENTS:
                    patterns.append(AttackPattern(
                        pattern_type="burst",
                        severity="critical",
                        description=(
                            f"IP {ip} made {count_in_window} attempts within "
                            f"{_BURST_WINDOW_SECONDS}s — automated attack burst"
                        ),
                        evidence={
                            "source_ip": ip,
                            "attempts_in_window": count_in_window,
                            "window_seconds": _BURST_WINDOW_SECONDS,
                        },
                    ))
                    break  # One burst finding per IP is sufficient

        # --- Brute force (high attempt count from single IP) ---
        brute_force_threshold = max(20, self._total_attempts // 10)
        for ip, count in self._ip_counter.most_common():
            if count >= brute_force_threshold and count >= 20:
                patterns.append(AttackPattern(
                    pattern_type="brute_force",
                    severity="medium",
                    description=(
                        f"IP {ip} made {count} total attempts — "
                        f"single-source brute force pattern"
                    ),
                    evidence={"source_ip": ip, "total_attempts": count},
                ))

        # Sort: critical → high → medium → low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        patterns.sort(key=lambda p: severity_order.get(p.severity, 99))
        return patterns

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def summary(self) -> dict:
        """
        Build an aggregate summary of all recorded attempts.

        Returns:
            Dictionary with summary statistics and detected patterns.
            No raw credentials are included.
        """
        patterns = self.detect_patterns()

        return {
            "total_attempts": self._total_attempts,
            "first_event_at": self._first_event_at.isoformat() if self._first_event_at else None,
            "last_event_at":  self._last_event_at.isoformat() if self._last_event_at else None,
            "distinct_source_ips": len(self._ip_counter),
            "distinct_usernames":  len(self._username_counter),
            "distinct_hash_prefixes": len(self._hash_prefix_counter),
            "top_usernames": [
                {"username": u, "attempts": c}
                for u, c in self._username_counter.most_common(self._top_n)
            ],
            "top_source_ips": [
                {"ip": ip, "attempts": c}
                for ip, c in self._ip_counter.most_common(self._top_n)
            ],
            "top_credential_hashes": [
                {"hash_prefix": hp, "attempts": c}
                for hp, c in self._hash_prefix_counter.most_common(self._top_n)
            ],
            "detected_patterns": [
                {
                    "pattern_type": p.pattern_type,
                    "severity": p.severity,
                    "description": p.description,
                    "evidence": p.evidence,
                }
                for p in patterns
            ],
        }

    def export_json(self, output_path: Path) -> Path:
        """
        Write the summary to a JSON file.

        Args:
            output_path: Destination path for the JSON report.

        Returns:
            The path that was written.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "service": "ssh",
            "summary": self.summary(),
        }
        output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return output_path

    def reset(self) -> None:
        """Clear all recorded data (useful for test isolation)."""
        self.__init__(top_n=self._top_n)
