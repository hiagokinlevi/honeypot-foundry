"""
Threat Intelligence Feed Enrichment
=====================================
Enriches honeypot events with threat intelligence from local or remote
feed sources — known malicious IP addresses, CIDR ranges, and threat actor
tags.

The enricher supports multiple feed formats:
  - Plain IP list (one IP or CIDR per line, # comments ignored)
  - CSV feeds with ip,category,confidence,tags columns
  - AbuseIPDB-style JSON export (blacklist endpoint response)
  - STIX-2 indicator bundles (pattern: ipv4-addr:value = '...')

Feeds are cached in memory with configurable TTL to avoid re-fetching on
every event. The local cache is a dict: IP string → ThreatIntelMatch.

Key classes:
  - ThreatIntelMatch:    Enrichment record for one IP.
  - FeedConfig:          Configuration for one threat intel feed source.
  - ThreatIntelEnricher: Main enricher with load/lookup/refresh/enrich API.

Usage:
    from analysis.threat_intel import ThreatIntelEnricher, FeedConfig

    enricher = ThreatIntelEnricher()
    enricher.load_feed_text(open("known_bad_ips.txt").read(), source="blocklist.de")

    match = enricher.lookup("185.220.101.1")
    if match:
        print(f"Known malicious: {match.categories} (score={match.confidence})")

    # Enrich a honeypot event dict in-place
    enricher.enrich_event(event)   # adds event["threat_intel"] key
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from io import StringIO
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntelMatch:
    """
    Threat intelligence match for a single IP address.

    Attributes:
        ip:           The matched IP address (exact or CIDR-derived).
        source:       Feed name/URL that provided this record.
        categories:   List of threat categories (e.g. "scanner", "tor-exit", "botnet").
        confidence:   0–100 score; higher = more reliable.
        tags:         Arbitrary key-value tags from the feed.
        matched_cidr: The CIDR range that matched, if the lookup was CIDR-based.
        last_seen:    ISO date string from the feed (if available).
        cached_at:    Unix timestamp when this record was cached.
    """
    ip:           str
    source:       str
    categories:   list[str]       = field(default_factory=list)
    confidence:   int             = 50
    tags:         dict[str, str]  = field(default_factory=dict)
    matched_cidr: Optional[str]   = None
    last_seen:    Optional[str]   = None
    cached_at:    float           = field(default_factory=time.time)

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 75

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip":           self.ip,
            "source":       self.source,
            "categories":   self.categories,
            "confidence":   self.confidence,
            "tags":         self.tags,
            "matched_cidr": self.matched_cidr,
            "last_seen":    self.last_seen,
            "cached_at":    self.cached_at,
        }


@dataclass
class FeedConfig:
    """
    Configuration for a single threat intel feed source.

    Attributes:
        name:           Friendly name for this feed.
        format:         "ip_list" | "csv" | "abuseipdb_json" | "stix2_json"
        default_confidence: Default confidence for entries from this feed (0–100).
        default_categories: Default category tags for all entries.
        ttl_seconds:    How long cached entries remain valid (default: 3600).
        ip_column:      For CSV feeds: column name containing the IP (default: "ip").
        category_column: For CSV feeds: column name for category (default: "category").
        confidence_column: For CSV feeds: column name for confidence score.
    """
    name:                 str
    format:               str = "ip_list"
    default_confidence:   int = 50
    default_categories:   list[str] = field(default_factory=list)
    ttl_seconds:          int = 3600
    ip_column:            str = "ip"
    category_column:      str = "category"
    confidence_column:    str = "confidence"


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def _is_valid_ip_or_cidr(s: str) -> bool:
    """Return True if s is a valid IPv4/IPv6 address or CIDR notation."""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def parse_ip_list(text: str, config: FeedConfig) -> list[ThreatIntelMatch]:
    """
    Parse a plain IP list feed.

    Format: one IP or CIDR per line. Lines starting with # are comments.
    Entries may have optional inline comments: 185.220.101.1 # tor-exit

    Returns a list of ThreatIntelMatch entries.
    """
    matches = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comment
        parts = line.split("#", 1)
        entry = parts[0].strip()
        comment = parts[1].strip() if len(parts) > 1 else ""

        if not _is_valid_ip_or_cidr(entry):
            continue

        tags = {}
        if comment:
            tags["comment"] = comment

        # Determine if this is a network or host
        try:
            net = ipaddress.ip_network(entry, strict=False)
            is_cidr = net.num_addresses > 1
        except ValueError:
            is_cidr = False

        matches.append(ThreatIntelMatch(
            ip=entry,
            source=config.name,
            categories=list(config.default_categories),
            confidence=config.default_confidence,
            tags=tags,
            matched_cidr=entry if is_cidr else None,
        ))
    return matches


def parse_csv_feed(text: str, config: FeedConfig) -> list[ThreatIntelMatch]:
    """
    Parse a CSV threat intel feed.

    Expected columns (configurable via FeedConfig):
      - ip (required)
      - category (optional)
      - confidence (optional, integer 0–100)
      - Any extra columns are captured as tags.

    Returns a list of ThreatIntelMatch entries.
    """
    matches = []
    reader = csv.DictReader(StringIO(text))
    for row in reader:
        ip = row.get(config.ip_column, "").strip()
        if not ip or not _is_valid_ip_or_cidr(ip):
            continue

        raw_cat = row.get(config.category_column, "").strip()
        categories = [raw_cat] if raw_cat else list(config.default_categories)

        try:
            confidence = int(row.get(config.confidence_column, config.default_confidence))
            confidence = max(0, min(100, confidence))
        except (ValueError, TypeError):
            confidence = config.default_confidence

        # All other columns become tags
        skip = {config.ip_column, config.category_column, config.confidence_column}
        tags = {k: v for k, v in row.items() if k not in skip and v}

        matches.append(ThreatIntelMatch(
            ip=ip,
            source=config.name,
            categories=categories,
            confidence=confidence,
            tags=tags,
        ))
    return matches


def parse_abuseipdb_json(text: str, config: FeedConfig) -> list[ThreatIntelMatch]:
    """
    Parse an AbuseIPDB-style JSON blacklist export.

    Expected structure (AbuseIPDB /blacklist endpoint):
    {
      "data": [
        {
          "ipAddress": "1.2.3.4",
          "abuseConfidenceScore": 100,
          "countryCode": "CN",
          "lastReportedAt": "2026-04-01T00:00:00+00:00"
        },
        ...
      ]
    }

    Returns a list of ThreatIntelMatch entries.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    entries = data.get("data", [])
    if not isinstance(entries, list):
        return []

    matches = []
    for entry in entries:
        ip = str(entry.get("ipAddress", "")).strip()
        if not ip or not _is_valid_ip_or_cidr(ip):
            continue

        confidence = int(entry.get("abuseConfidenceScore", config.default_confidence))
        confidence = max(0, min(100, confidence))

        tags = {}
        country = entry.get("countryCode")
        if country:
            tags["country"] = country
        total_reports = entry.get("totalReports")
        if total_reports is not None:
            tags["total_reports"] = str(total_reports)

        last_seen = entry.get("lastReportedAt") or entry.get("lastSeen")

        matches.append(ThreatIntelMatch(
            ip=ip,
            source=config.name,
            categories=list(config.default_categories) or ["abuse"],
            confidence=confidence,
            tags=tags,
            last_seen=last_seen,
        ))
    return matches


def parse_stix2_json(text: str, config: FeedConfig) -> list[ThreatIntelMatch]:
    """
    Parse a STIX-2 indicator bundle for IPv4 address indicators.

    Handles:
      - pattern: "[ipv4-addr:value = '1.2.3.4']"
      - pattern: "[ipv4-addr:value = '10.0.0.0/8']"

    Returns a list of ThreatIntelMatch entries.
    """
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError:
        return []

    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        return []

    _IP_PATTERN = re.compile(
        r"ipv4-addr:value\s*=\s*['\"]([0-9./]+)['\"]", re.IGNORECASE
    )

    matches = []
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for m in _IP_PATTERN.finditer(pattern):
            ip = m.group(1).strip()
            if not _is_valid_ip_or_cidr(ip):
                continue

            # Extract labels/categories
            labels = obj.get("labels", [])
            categories = labels if labels else list(config.default_categories)

            tags = {}
            indicator_name = obj.get("name")
            if indicator_name:
                tags["indicator_name"] = indicator_name
            stix_id = obj.get("id")
            if stix_id:
                tags["stix_id"] = stix_id

            last_seen = obj.get("valid_until") or obj.get("modified")

            matches.append(ThreatIntelMatch(
                ip=ip,
                source=config.name,
                categories=categories,
                confidence=config.default_confidence,
                tags=tags,
                last_seen=last_seen,
            ))
    return matches


# ---------------------------------------------------------------------------
# ThreatIntelEnricher
# ---------------------------------------------------------------------------

_DEFAULT_TTL = 3600  # 1 hour default cache TTL


class ThreatIntelEnricher:
    """
    Enriches honeypot events with threat intelligence from loaded feeds.

    Maintains an in-memory cache of:
      - Exact IP → ThreatIntelMatch   (fast O(1) lookup)
      - IPv4Network objects for CIDR range matching (O(n) scan, n = CIDR count)

    Feeds are loaded via load_feed_text() or load_feed_json().
    Entries expire after their source feed's TTL seconds.

    Thread safety: Not thread-safe. Use one instance per process or add
    external locking for concurrent use.
    """

    def __init__(self, default_ttl: int = _DEFAULT_TTL) -> None:
        self._exact: dict[str, ThreatIntelMatch] = {}
        self._cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatIntelMatch]] = []
        self._default_ttl = default_ttl

    # ------------------------------------------------------------------
    # Feed loading
    # ------------------------------------------------------------------

    def load_feed_text(
        self,
        text: str,
        source: str = "manual",
        fmt: str = "ip_list",
        default_confidence: int = 50,
        default_categories: Optional[list[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> int:
        """
        Load threat intel from a text string.

        Args:
            text:                 Feed content as a string.
            source:               Human-readable feed name.
            fmt:                  "ip_list" | "csv" | "abuseipdb_json" | "stix2_json"
            default_confidence:   Default confidence score (0–100).
            default_categories:   Default category tags.
            ttl_seconds:          Cache TTL; defaults to self._default_ttl.

        Returns:
            Number of entries loaded.
        """
        config = FeedConfig(
            name=source,
            format=fmt,
            default_confidence=default_confidence,
            default_categories=default_categories or [],
            ttl_seconds=ttl_seconds or self._default_ttl,
        )

        parsers = {
            "ip_list":       parse_ip_list,
            "csv":           parse_csv_feed,
            "abuseipdb_json": parse_abuseipdb_json,
            "stix2_json":    parse_stix2_json,
        }
        parser = parsers.get(fmt, parse_ip_list)
        matches = parser(text, config)
        self._ingest(matches)
        return len(matches)

    def _ingest(self, matches: list[ThreatIntelMatch]) -> None:
        """Store matches in exact and CIDR lookup structures."""
        for match in matches:
            try:
                net = ipaddress.ip_network(match.ip, strict=False)
                if net.num_addresses == 1:
                    # Exact host
                    self._exact[str(net.network_address)] = match
                else:
                    # CIDR range
                    match.matched_cidr = match.ip
                    self._cidrs.append((net, match))
            except ValueError:
                continue

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, ip: str) -> Optional[ThreatIntelMatch]:
        """
        Look up a single IP address against loaded threat intel.

        Checks exact matches first, then CIDR ranges.
        Returns None if no match found or all matches are expired.

        Args:
            ip: IP address string to look up.

        Returns:
            ThreatIntelMatch if the IP is in any loaded feed, else None.
        """
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None

        addr_str = str(addr)
        now = time.time()

        # Step 1: Exact match
        if addr_str in self._exact:
            match = self._exact[addr_str]
            # Check TTL
            if now - match.cached_at <= self._default_ttl:
                return match
            else:
                del self._exact[addr_str]

        # Step 2: CIDR range scan
        for net, match in self._cidrs:
            if addr in net:
                if now - match.cached_at <= self._default_ttl:
                    return ThreatIntelMatch(
                        ip=addr_str,
                        source=match.source,
                        categories=list(match.categories),
                        confidence=match.confidence,
                        tags=dict(match.tags),
                        matched_cidr=str(net),
                        last_seen=match.last_seen,
                        cached_at=match.cached_at,
                    )

        return None

    def lookup_batch(self, ips: list[str]) -> dict[str, Optional[ThreatIntelMatch]]:
        """
        Look up multiple IPs. Returns a dict mapping each IP to its match (or None).
        """
        return {ip: self.lookup(ip) for ip in ips}

    # ------------------------------------------------------------------
    # Event enrichment
    # ------------------------------------------------------------------

    def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a honeypot event dict in-place with threat intel.

        Looks up the source IP from:
          event["source_ip"] or event["src_ip"] or event["ip"] or event["remote_ip"]

        Adds event["threat_intel"] with enrichment data, or
        event["threat_intel"] = None if no match.

        Args:
            event: Honeypot event dict (mutated in-place).

        Returns:
            The same event dict with threat_intel field added.
        """
        ip = (
            event.get("source_ip")
            or event.get("src_ip")
            or event.get("ip")
            or event.get("remote_ip")
            or ""
        )
        match = self.lookup(str(ip)) if ip else None
        event["threat_intel"] = match.to_dict() if match else None
        return event

    def enrich_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich a list of events in-place. Returns the same list."""
        for event in events:
            self.enrich_event(event)
        return events

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def expire_stale(self) -> int:
        """
        Remove expired entries from the cache.

        Returns the number of entries removed.
        """
        now = time.time()
        removed = 0

        stale_keys = [
            k for k, v in self._exact.items()
            if now - v.cached_at > self._default_ttl
        ]
        for k in stale_keys:
            del self._exact[k]
            removed += 1

        original_cidr_len = len(self._cidrs)
        self._cidrs = [
            (net, m) for net, m in self._cidrs
            if now - m.cached_at <= self._default_ttl
        ]
        removed += original_cidr_len - len(self._cidrs)
        return removed

    def clear(self) -> None:
        """Remove all cached threat intel entries."""
        self._exact.clear()
        self._cidrs.clear()

    @property
    def entry_count(self) -> int:
        """Total number of cached threat intel entries (exact + CIDR)."""
        return len(self._exact) + len(self._cidrs)

    def stats(self) -> dict[str, Any]:
        """Return a stats dict for monitoring and reporting."""
        return {
            "exact_entries":  len(self._exact),
            "cidr_entries":   len(self._cidrs),
            "total_entries":  self.entry_count,
            "default_ttl":    self._default_ttl,
        }
