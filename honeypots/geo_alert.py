"""
IP Geolocation Risk Alerter
==============================
Assigns risk scores to honeypot connection sources based on geographic
and network-level signals: high-risk country codes, anonymizing proxy/VPN
ASN patterns, hosting provider ranges, and Tor exit indicators.

Operates on structured GeoRecord inputs — no live GeoIP API calls are needed
(feed it pre-resolved data or use stub lookups for testing).

Risk Signals
------------
GEO-001   Connection from high-risk country code
GEO-002   ASN belongs to known hosting/cloud provider (not residential)
GEO-003   ASN name contains anonymizer/proxy keyword
GEO-004   IP is in a known Tor exit node list
GEO-005   Simultaneous connections from same ASN > threshold (ASN burst)

Usage::

    from honeypots.geo_alert import GeoAlertEngine, GeoRecord

    record = GeoRecord(
        ip="198.51.100.1",
        country_code="RU",
        asn=12345,
        asn_name="DigitalOcean LLC",
        is_tor=False,
    )
    engine = GeoAlertEngine(high_risk_countries={"RU", "CN", "KP", "IR"})
    alert = engine.evaluate(record)
    print(alert.risk_score, alert.signals)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Keyword lists for ASN classification
# ---------------------------------------------------------------------------

_HOSTING_KEYWORDS: List[str] = [
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "aws",
    "amazon",
    "google",
    "microsoft",
    "cloudflare",
    "contabo",
    "hostinger",
    "namecheap",
    "leaseweb",
]

_ANONYMIZER_KEYWORDS: List[str] = [
    "vpn",
    "proxy",
    "tor",
    "anonymize",
    "hide",
    "private",
    "tunnel",
    "nordvpn",
    "expressvpn",
    "mullvad",
    "proton",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class GeoRiskLevel(Enum):
    """Categorical risk levels derived from numeric score thresholds."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class GeoRecord:
    """Structured input representing a single resolved IP geolocation record.

    Attributes:
        ip:           The IP address string of the connecting host.
        country_code: ISO-3166-1 alpha-2 country code (empty string if unknown).
        asn:          Autonomous System Number (0 if unknown).
        asn_name:     Human-readable ASN / organisation name.
        is_tor:       True when the source IP is a known Tor exit node per
                      the resolver that produced this record.
        metadata:     Arbitrary key/value pairs for caller-supplied context
                      (e.g. reverse DNS, threat-feed tags).
    """

    ip: str
    country_code: str = ""
    asn: int = 0
    asn_name: str = ""
    is_tor: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class GeoSignal:
    """A single risk signal that fired during evaluation.

    Attributes:
        signal_id:          Stable identifier (e.g. "GEO-001").
        title:              Short human-readable label.
        score_contribution: Integer points added to the overall risk score.
        detail:             Contextual explanation for this specific record.
    """

    signal_id: str
    title: str
    score_contribution: int
    detail: str


@dataclass
class GeoAlert:
    """Output produced by :class:`GeoAlertEngine` for a single IP record.

    Attributes:
        ip:           Evaluated IP address.
        country_code: Country code from the source record.
        risk_score:   Aggregate risk score (0–100, capped).
        risk_level:   Categorical risk level derived from risk_score.
        signals:      Ordered list of signals that fired.
        is_tor:       Whether the IP was identified as a Tor exit node.
        generated_at: Unix timestamp (float) when this alert was created.
    """

    ip: str
    country_code: str
    risk_score: int
    risk_level: GeoRiskLevel
    signals: List[GeoSignal]
    is_tor: bool
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation.

        The ``risk_level`` field is serialised as its string value and each
        ``GeoSignal`` is converted to a plain dict.
        """
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,  # e.g. "HIGH"
            "signals": [
                {
                    "signal_id": s.signal_id,
                    "title": s.title,
                    "score_contribution": s.score_contribution,
                    "detail": s.detail,
                }
                for s in self.signals
            ],
            "is_tor": self.is_tor,
            "generated_at": self.generated_at,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of this alert.

        Format::

            <ip> [<country_code>] risk=<risk_score> (<risk_level>): <n> signal(s)
        """
        return (
            f"{self.ip} [{self.country_code}] risk={self.risk_score} "
            f"({self.risk_level.value}): {len(self.signals)} signal(s)"
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GeoAlertEngine:
    """Evaluates :class:`GeoRecord` objects and produces :class:`GeoAlert` results.

    The engine is stateful with respect to ASN burst tracking: each call to
    :meth:`evaluate` increments an internal per-ASN counter so that repeated
    connections from the same autonomous system can be detected across a
    session.  Call :meth:`reset_asn_counts` to clear this state between
    analysis windows.

    Args:
        high_risk_countries: Set of ISO-3166-1 alpha-2 country codes that
            trigger GEO-001.  Defaults to ``{"KP", "IR"}``.
        tor_exit_ips:        Optional set of known Tor exit IP strings that
            supplement the ``is_tor`` field on the record (GEO-004).
        asn_burst_threshold: Number of connections from a single ASN above
            which GEO-005 fires.  Defaults to 5.
    """

    def __init__(
        self,
        high_risk_countries: Optional[set] = None,
        tor_exit_ips: Optional[set] = None,
        asn_burst_threshold: int = 5,
    ) -> None:
        # Minimal default — callers should supply their own threat-intel list.
        self.high_risk_countries: set = (
            high_risk_countries if high_risk_countries is not None else {"KP", "IR"}
        )
        self.tor_exit_ips: Optional[set] = tor_exit_ips
        self.asn_burst_threshold: int = asn_burst_threshold

        # Internal counter for ASN burst detection (GEO-005).
        self._asn_counts: Dict[int, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, record: GeoRecord) -> GeoAlert:
        """Evaluate a single :class:`GeoRecord` and return a :class:`GeoAlert`.

        ASN burst state is updated as a side-effect of each call so that
        burst detection works correctly when :meth:`evaluate_many` delegates
        here.

        Args:
            record: Pre-resolved geolocation record to score.

        Returns:
            A :class:`GeoAlert` containing the computed score, level, and
            every signal that fired.
        """
        signals: List[GeoSignal] = []

        # ---- GEO-001: High-risk country --------------------------------
        if record.country_code and record.country_code in self.high_risk_countries:
            signals.append(
                GeoSignal(
                    signal_id="GEO-001",
                    title="High-risk country code",
                    score_contribution=35,
                    detail=(
                        f"Country code '{record.country_code}' is in the "
                        "high-risk country list."
                    ),
                )
            )

        # ---- GEO-002: Hosting / cloud provider ASN ---------------------
        asn_lower = record.asn_name.lower()
        matched_hosting = next(
            (kw for kw in _HOSTING_KEYWORDS if kw in asn_lower), None
        )
        if matched_hosting:
            signals.append(
                GeoSignal(
                    signal_id="GEO-002",
                    title="Hosting/cloud provider ASN",
                    score_contribution=20,
                    detail=(
                        f"ASN name '{record.asn_name}' matches hosting keyword "
                        f"'{matched_hosting}'."
                    ),
                )
            )

        # ---- GEO-003: Anonymizer / proxy keyword in ASN name -----------
        matched_anon = next(
            (kw for kw in _ANONYMIZER_KEYWORDS if kw in asn_lower), None
        )
        if matched_anon:
            signals.append(
                GeoSignal(
                    signal_id="GEO-003",
                    title="Anonymizer/proxy ASN",
                    score_contribution=30,
                    detail=(
                        f"ASN name '{record.asn_name}' matches anonymizer keyword "
                        f"'{matched_anon}'."
                    ),
                )
            )

        # ---- GEO-004: Tor exit node ------------------------------------
        is_tor_confirmed = record.is_tor or (
            self.tor_exit_ips is not None and record.ip in self.tor_exit_ips
        )
        if is_tor_confirmed:
            signals.append(
                GeoSignal(
                    signal_id="GEO-004",
                    title="Tor exit node",
                    score_contribution=40,
                    detail=(
                        f"IP '{record.ip}' identified as a Tor exit node "
                        f"(record.is_tor={record.is_tor}, "
                        f"in tor_exit_ips={self.tor_exit_ips is not None and record.ip in (self.tor_exit_ips or set())})."
                    ),
                )
            )

        # ---- GEO-005: ASN burst ----------------------------------------
        if record.asn:  # skip unknown ASN (0)
            self._asn_counts[record.asn] = self._asn_counts.get(record.asn, 0) + 1
            if self._asn_counts[record.asn] > self.asn_burst_threshold:
                signals.append(
                    GeoSignal(
                        signal_id="GEO-005",
                        title="ASN burst threshold exceeded",
                        score_contribution=25,
                        detail=(
                            f"ASN {record.asn} has {self._asn_counts[record.asn]} "
                            f"connections, exceeding burst threshold of "
                            f"{self.asn_burst_threshold}."
                        ),
                    )
                )

        # ---- Aggregate score and level ---------------------------------
        raw_score = sum(s.score_contribution for s in signals)
        risk_score = min(100, raw_score)
        risk_level = _score_to_level(risk_score)

        return GeoAlert(
            ip=record.ip,
            country_code=record.country_code,
            risk_score=risk_score,
            risk_level=risk_level,
            signals=signals,
            is_tor=is_tor_confirmed,
        )

    def evaluate_many(self, records: List[GeoRecord]) -> List[GeoAlert]:
        """Evaluate a list of records in order, returning a list of alerts.

        ASN burst state accumulates across all records in the list.  The
        returned list preserves the input order and has the same length.

        Args:
            records: Sequence of :class:`GeoRecord` objects to evaluate.

        Returns:
            A list of :class:`GeoAlert` objects, one per input record.
        """
        return [self.evaluate(record) for record in records]

    def reset_asn_counts(self) -> None:
        """Clear all accumulated ASN burst counters.

        Call this between time windows or analysis sessions to prevent burst
        state from a previous window contaminating the next.
        """
        self._asn_counts.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _score_to_level(score: int) -> GeoRiskLevel:
    """Map a numeric risk score to a :class:`GeoRiskLevel` category.

    Thresholds (inclusive lower bound):
      - CRITICAL: score >= 80
      - HIGH:     score >= 55
      - MEDIUM:   score >= 35
      - LOW:      score >= 15
      - INFO:     score <  15
    """
    if score >= 80:
        return GeoRiskLevel.CRITICAL
    if score >= 55:
        return GeoRiskLevel.HIGH
    if score >= 35:
        return GeoRiskLevel.MEDIUM
    if score >= 15:
        return GeoRiskLevel.LOW
    return GeoRiskLevel.INFO
