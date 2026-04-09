"""
Tests for analysis/alert_dedup.py

Validates:
  - First event always generates an alert
  - Duplicate event within window is deduplicated (should_alert=False)
  - Duplicate event after window expiry generates a new alert
  - Different IPs with same credential are NOT deduplicated
  - Different credentials from same IP are NOT deduplicated
  - SuppressionRule.matches() by ip_prefix, username_pattern, service
  - Expired suppression rules are not applied
  - max_group_size exceeded triggers re-alert
  - expire_old_groups() removes expired windows
  - Counters: total_processed, total_suppressed, total_alerted, total_deduplicated
  - add_rule() and remove_expired_rules()
  - active_group_count property
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.alert_dedup import AlertDedup, DedupConfig, DedupResult, SuppressionRule
from honeypots.common.event import HoneypotEvent, ServiceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    source_ip: str = "1.2.3.4",
    service: ServiceType = ServiceType.SSH,
    credential: str = "password123",
    username: str = "root",
    user_agent: str | None = None,
    ts: datetime | None = None,
) -> HoneypotEvent:
    return HoneypotEvent(
        timestamp=ts or _now(),
        service=service,
        source_ip=source_ip,
        source_port=22,
        username=username,
        credential_observed=credential,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Basic deduplication
# ---------------------------------------------------------------------------

class TestBasicDedup:

    def test_first_event_triggers_alert(self):
        dedup = AlertDedup()
        result = dedup.process(_event(), now=_now())
        assert result.should_alert is True

    def test_duplicate_within_window_no_alert(self):
        dedup = AlertDedup(config=DedupConfig(window_seconds=300))
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        # Same IP, service, credential — 60s later (within 300s window)
        result = dedup.process(_event(ts=t0 + timedelta(seconds=60)), now=t0 + timedelta(seconds=60))
        assert result.should_alert is False

    def test_duplicate_after_window_triggers_new_alert(self):
        dedup = AlertDedup(config=DedupConfig(window_seconds=300))
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        # Same event, 400s later — window expired
        t1 = t0 + timedelta(seconds=400)
        result = dedup.process(_event(ts=t1), now=t1)
        assert result.should_alert is True

    def test_different_ips_not_deduped(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(source_ip="1.2.3.4", ts=t0), now=t0)
        result = dedup.process(_event(source_ip="5.6.7.8", ts=t0), now=t0)
        assert result.should_alert is True

    def test_different_services_not_deduped(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(service=ServiceType.SSH, ts=t0), now=t0)
        result = dedup.process(_event(service=ServiceType.HTTP, ts=t0), now=t0)
        assert result.should_alert is True

    def test_different_credentials_not_deduped(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(credential="pass1", ts=t0), now=t0)
        result = dedup.process(_event(credential="pass2", ts=t0), now=t0)
        assert result.should_alert is True

    def test_dedup_result_has_representative_event(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        result = dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))
        assert result.representative_event is not None

    def test_dedup_result_group_event_count_increments(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        result = dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))
        assert result.group_event_count == 2

    def test_dedup_result_not_suppressed(self):
        dedup = AlertDedup()
        result = dedup.process(_event(), now=_now())
        assert result.suppressed is False
        assert result.suppression_reason is None


# ---------------------------------------------------------------------------
# max_group_size re-alert
# ---------------------------------------------------------------------------

class TestMaxGroupSize:

    def test_re_alert_when_max_group_size_exceeded(self):
        # max_group_size=4: events 1+2+3 deduplicate; event 4 hits limit → re-alert
        dedup = AlertDedup(config=DedupConfig(window_seconds=300, max_group_size=4))
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)                                      # alert (count=1)
        dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))   # dedup (count=2)
        dedup.process(_event(ts=t0 + timedelta(seconds=20)), now=t0 + timedelta(seconds=20))   # dedup (count=3)
        result = dedup.process(_event(ts=t0 + timedelta(seconds=30)), now=t0 + timedelta(seconds=30))  # count=4 >= 4 → re-alert
        assert result.should_alert is True

    def test_counter_resets_after_max_group_exceeded(self):
        dedup = AlertDedup(config=DedupConfig(window_seconds=300, max_group_size=2))
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        result = dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))
        # After reset, next event in same window is treated as fresh
        result2 = dedup.process(_event(ts=t0 + timedelta(seconds=20)), now=t0 + timedelta(seconds=20))
        assert result2.should_alert is True


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------

class TestSuppressionRules:

    def test_suppress_by_ip_prefix(self):
        rule = SuppressionRule(ip_prefix="10.", reason="internal")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(source_ip="10.0.0.5"), now=_now())
        assert result.suppressed is True
        assert result.should_alert is False

    def test_suppress_reason_returned(self):
        rule = SuppressionRule(ip_prefix="10.", reason="internal scanner")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(source_ip="10.0.0.1"), now=_now())
        assert result.suppression_reason == "internal scanner"

    def test_suppress_by_username_pattern(self):
        rule = SuppressionRule(username_pattern=r"^test_", reason="test accounts")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(username="test_user"), now=_now())
        assert result.suppressed is True

    def test_no_suppress_non_matching_username(self):
        rule = SuppressionRule(username_pattern=r"^test_", reason="test accounts")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(username="admin"), now=_now())
        assert result.suppressed is False

    def test_suppress_by_service(self):
        rule = SuppressionRule(service=ServiceType.HTTP, reason="HTTP noise")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(service=ServiceType.HTTP), now=_now())
        assert result.suppressed is True

    def test_no_suppress_different_service(self):
        rule = SuppressionRule(service=ServiceType.HTTP, reason="HTTP noise")
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(service=ServiceType.SSH), now=_now())
        assert result.suppressed is False

    def test_expired_suppression_rule_not_applied(self):
        past = datetime(2025, 1, 1, tzinfo=timezone.utc)
        rule = SuppressionRule(ip_prefix="10.", reason="expired rule", expires=past)
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(source_ip="10.0.0.1"), now=_now())
        # Rule is expired — should NOT suppress
        assert result.suppressed is False

    def test_active_expiry_suppresses(self):
        future = _now() + timedelta(hours=24)
        rule = SuppressionRule(ip_prefix="10.", reason="active rule", expires=future)
        dedup = AlertDedup(suppression_rules=[rule])
        result = dedup.process(_event(source_ip="10.0.0.1"), now=_now())
        assert result.suppressed is True

    def test_add_rule_at_runtime(self):
        dedup = AlertDedup()
        dedup.add_rule(SuppressionRule(ip_prefix="192.168.", reason="local"))
        result = dedup.process(_event(source_ip="192.168.1.100"), now=_now())
        assert result.suppressed is True

    def test_remove_expired_rules(self):
        past = datetime(2025, 1, 1, tzinfo=timezone.utc)
        future = _now() + timedelta(hours=1)
        dedup = AlertDedup(suppression_rules=[
            SuppressionRule(ip_prefix="10.", reason="expired", expires=past),
            SuppressionRule(ip_prefix="172.", reason="active", expires=future),
        ])
        removed = dedup.remove_expired_rules(now=_now())
        assert removed == 1
        assert len(dedup._rules) == 1


# ---------------------------------------------------------------------------
# Counters and housekeeping
# ---------------------------------------------------------------------------

class TestCounters:

    def test_total_processed_increments(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))
        assert dedup.total_processed == 2

    def test_total_alerted_increments_on_new_alert(self):
        dedup = AlertDedup()
        dedup.process(_event(), now=_now())
        assert dedup.total_alerted == 1

    def test_total_deduplicated_increments(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(ts=t0), now=t0)
        dedup.process(_event(ts=t0 + timedelta(seconds=10)), now=t0 + timedelta(seconds=10))
        assert dedup.total_deduplicated == 1

    def test_total_suppressed_increments(self):
        rule = SuppressionRule(ip_prefix="10.", reason="internal")
        dedup = AlertDedup(suppression_rules=[rule])
        dedup.process(_event(source_ip="10.0.0.1"), now=_now())
        assert dedup.total_suppressed == 1

    def test_active_group_count(self):
        dedup = AlertDedup()
        t0 = _now()
        dedup.process(_event(source_ip="1.1.1.1", ts=t0), now=t0)
        dedup.process(_event(source_ip="2.2.2.2", ts=t0), now=t0)
        assert dedup.active_group_count == 2

    def test_expire_old_groups_removes_expired(self):
        dedup = AlertDedup(config=DedupConfig(window_seconds=60))
        t0 = _now()
        dedup.process(_event(source_ip="1.1.1.1", ts=t0), now=t0)
        # Advance time past window
        t1 = t0 + timedelta(seconds=120)
        removed = dedup.expire_old_groups(now=t1)
        assert removed == 1
        assert dedup.active_group_count == 0

    def test_expire_old_groups_keeps_active_groups(self):
        dedup = AlertDedup(config=DedupConfig(window_seconds=300))
        t0 = _now()
        dedup.process(_event(source_ip="1.1.1.1", ts=t0), now=t0)
        t1 = t0 + timedelta(seconds=100)  # Still within window
        removed = dedup.expire_old_groups(now=t1)
        assert removed == 0
        assert dedup.active_group_count == 1
