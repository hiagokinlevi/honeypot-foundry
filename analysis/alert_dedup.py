"""
Alert Deduplication and Suppression Engine
===========================================
Prevents alert floods by deduplicating honeypot events that share the same
source IP + service + credential hash, and by suppressing events from
known-safe IP ranges (internal scanners, testing infrastructure).

Core concepts:
  DedupWindow:
    Within a given time window, multiple events with the same (source_ip,
    service, credential_hash_prefix) are collapsed into a single alert.
    Events outside the window start a new dedup group.

  SuppressionRule:
    Permanently silences events from a specific source IP, CIDR prefix, or
    matching a given username pattern. Suppressed events are counted but not
    forwarded to downstream alerting.

Usage:
    from analysis.alert_dedup import AlertDedup, SuppressionRule, DedupConfig

    dedup = AlertDedup(
        config=DedupConfig(window_seconds=300, max_group_size=50),
        suppression_rules=[
            SuppressionRule(ip_prefix="10.", reason="Internal network scanner"),
            SuppressionRule(ip_prefix="192.168.", reason="Local test traffic"),
        ],
    )

    for event in events:
        result = dedup.process(event)
        if result.should_alert:
            send_to_siem(result.representative_event)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from honeypots.common.event import HoneypotEvent, ServiceType


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class DedupConfig:
    """
    Configuration for the deduplication window.

    Attributes:
        window_seconds:  Events with the same key within this many seconds
                         are merged into one group. Default: 300 (5 minutes).
        max_group_size:  Maximum events per dedup group before forcing a new
                         alert (prevents indefinite suppression of flooding
                         sources). Default: 100.
    """
    window_seconds: int = 300
    max_group_size: int = 100


@dataclass(frozen=True)
class SuppressionRule:
    """
    A rule that permanently silences events matching a pattern.

    Match criteria (at least one required):
        ip_prefix:        Events from IPs starting with this prefix are suppressed
                          (e.g., "10." for all RFC 1918 Class-A addresses).
        username_pattern: Regex pattern matched against the event's username field.
                          Events where the username matches are suppressed.
        service:          Suppress all events for a specific ServiceType.

    Attributes:
        reason:  Human-readable explanation (shown in suppression logs).
        added_by: Who added this rule (optional, for audit trail).
        expires:  Optional UTC datetime after which this rule stops applying.
    """
    reason:           str
    ip_prefix:        Optional[str]         = None
    username_pattern: Optional[str]         = None
    service:          Optional[ServiceType] = None
    added_by:         Optional[str]         = None
    expires:          Optional[datetime]    = None

    def matches(self, event: HoneypotEvent, now: Optional[datetime] = None) -> bool:
        """Return True if this rule suppresses the given event."""
        if self.expires is not None:
            check_time = now or datetime.now(tz=timezone.utc)
            if check_time > self.expires:
                return False   # Rule expired

        if self.ip_prefix and not event.source_ip.startswith(self.ip_prefix):
            return False

        if self.username_pattern and event.username:
            if not re.search(self.username_pattern, event.username, re.IGNORECASE):
                return False
        elif self.username_pattern and not event.username:
            return False

        if self.service and event.service != self.service:
            return False

        return True


# ---------------------------------------------------------------------------
# Dedup group — tracks a window of related events
# ---------------------------------------------------------------------------

@dataclass
class _DedupGroup:
    """Internal — one dedup bucket for a (ip, service, credential_key) tuple."""
    first_seen:         datetime
    last_seen:          datetime
    event_count:        int
    representative:     HoneypotEvent   # The first event that opened this group


def _credential_key(event: HoneypotEvent) -> str:
    """
    Return a stable, non-sensitive key for the event's credential.

    Uses the hash_prefix embedded in the masked credential string if available,
    so two events with the same raw credential produce the same dedup key.
    """
    if event.credential_observed and "hash_prefix=" in event.credential_observed:
        # Extract: [masked:len=N,hash_prefix=XXXXXXXX]
        match = re.search(r"hash_prefix=([0-9a-f]+)", event.credential_observed)
        if match:
            return match.group(1)
    return event.credential_observed or "__no_cred__"


# ---------------------------------------------------------------------------
# Dedup result
# ---------------------------------------------------------------------------

@dataclass
class DedupResult:
    """
    Result of processing a single event through the dedup engine.

    Attributes:
        should_alert:         True if this event opens a new dedup window OR
                              the group has exceeded max_group_size (re-alert).
        suppressed:           True if a SuppressionRule matched this event.
        suppression_reason:   Reason string from the matching rule, or None.
        representative_event: The first event in this dedup group (suitable
                              for forwarding to a SIEM). None if suppressed.
        group_event_count:    Total events seen in the current dedup window.
        dedup_key:            The (ip, service, credential) key string.
    """
    should_alert:         bool
    suppressed:           bool
    suppression_reason:   Optional[str]
    representative_event: Optional[HoneypotEvent]
    group_event_count:    int
    dedup_key:            str


# ---------------------------------------------------------------------------
# AlertDedup
# ---------------------------------------------------------------------------

class AlertDedup:
    """
    Stateful deduplication and suppression engine for honeypot events.

    Maintains an in-memory window of recent event groups. Call `process()`
    for each incoming event; act on `result.should_alert` to decide whether
    to forward to SIEM or alerting systems.

    Thread safety: not thread-safe. Use one instance per consumer goroutine/
    process, or protect with an external lock.

    Args:
        config:            DedupConfig with window_seconds and max_group_size.
        suppression_rules: List of SuppressionRule objects applied before dedup.
    """

    def __init__(
        self,
        config: Optional[DedupConfig] = None,
        suppression_rules: Optional[list[SuppressionRule]] = None,
    ) -> None:
        self._config    = config or DedupConfig()
        self._rules     = list(suppression_rules or [])
        # Key: (source_ip, service, credential_key) → _DedupGroup
        self._groups:   dict[str, _DedupGroup] = {}
        # Counters for reporting
        self.total_processed:  int = 0
        self.total_suppressed: int = 0
        self.total_alerted:    int = 0
        self.total_deduplicated: int = 0

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: SuppressionRule) -> None:
        """Add a suppression rule at runtime."""
        self._rules.append(rule)

    def remove_expired_rules(self, now: Optional[datetime] = None) -> int:
        """Remove suppression rules past their expiry date. Returns count removed."""
        cutoff = now or datetime.now(tz=timezone.utc)
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.expires is None or r.expires > cutoff]
        return before - len(self._rules)

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def process(
        self,
        event: HoneypotEvent,
        now: Optional[datetime] = None,
    ) -> DedupResult:
        """
        Process one honeypot event through suppression and deduplication.

        Args:
            event: Incoming HoneypotEvent (credentials must already be masked).
            now:   Override for current time (useful in tests). Defaults to UTC now.

        Returns:
            DedupResult describing the dedup decision.
        """
        self.total_processed += 1
        current_time = now or datetime.now(tz=timezone.utc)

        # --- Suppression check ---
        for rule in self._rules:
            if rule.matches(event, now=current_time):
                self.total_suppressed += 1
                return DedupResult(
                    should_alert=False,
                    suppressed=True,
                    suppression_reason=rule.reason,
                    representative_event=None,
                    group_event_count=1,
                    dedup_key=self._make_key(event),
                )

        # --- Deduplication ---
        key = self._make_key(event)
        window = timedelta(seconds=self._config.window_seconds)
        group = self._groups.get(key)

        if group is None or (current_time - group.last_seen) > window:
            # New group or window expired — open fresh group and alert
            self._groups[key] = _DedupGroup(
                first_seen=current_time,
                last_seen=current_time,
                event_count=1,
                representative=event,
            )
            self.total_alerted += 1
            return DedupResult(
                should_alert=True,
                suppressed=False,
                suppression_reason=None,
                representative_event=event,
                group_event_count=1,
                dedup_key=key,
            )

        # Existing window — merge into group
        group.last_seen = current_time
        group.event_count += 1

        if group.event_count >= self._config.max_group_size:
            # Group exceeded size limit — re-alert and reset
            self._groups[key] = _DedupGroup(
                first_seen=current_time,
                last_seen=current_time,
                event_count=1,
                representative=event,
            )
            self.total_alerted += 1
            return DedupResult(
                should_alert=True,
                suppressed=False,
                suppression_reason=None,
                representative_event=event,
                group_event_count=group.event_count,
                dedup_key=key,
            )

        # Duplicate within window — silently absorb
        self.total_deduplicated += 1
        return DedupResult(
            should_alert=False,
            suppressed=False,
            suppression_reason=None,
            representative_event=group.representative,
            group_event_count=group.event_count,
            dedup_key=key,
        )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def expire_old_groups(self, now: Optional[datetime] = None) -> int:
        """
        Remove dedup groups whose window has expired. Call periodically to
        prevent unbounded memory growth.

        Returns the number of groups removed.
        """
        cutoff = (now or datetime.now(tz=timezone.utc)) - timedelta(
            seconds=self._config.window_seconds
        )
        expired = [k for k, g in self._groups.items() if g.last_seen < cutoff]
        for k in expired:
            del self._groups[k]
        return len(expired)

    @property
    def active_group_count(self) -> int:
        """Number of currently active dedup groups."""
        return len(self._groups)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(event: HoneypotEvent) -> str:
        return f"{event.source_ip}|{event.service.value}|{_credential_key(event)}"
