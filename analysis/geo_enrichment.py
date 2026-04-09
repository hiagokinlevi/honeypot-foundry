"""
IP Geo-Enrichment for Honeypot Events
=======================================
Adds geographic and ASN context to honeypot events by resolving the source IP
to a country, city, and autonomous system number.

Two resolution backends are supported:
  1. MaxMind GeoLite2 (preferred) — fast, offline, accurate. Requires the
     free GeoLite2-City.mmdb database file. Install with:
       pip install maxminddb
     Then set MAXMIND_DB_PATH in your environment or pass db_path explicitly.

  2. Built-in stub table (fallback) — recognises well-known IP ranges
     (Cloudflare, Google, AWS, RFC 1918 private ranges) without external deps.
     Used automatically when maxminddb is not installed or no db_path is given.

Usage:
    from analysis.geo_enrichment import GeoInfo, enrich_ip, enrich_event

    info = enrich_ip("8.8.8.8")
    print(info.country_code)   # "US"
    print(info.org)            # "Google LLC"

    enriched_event = enrich_event(event)
    print(enriched_event.metadata["geo"])  # GeoInfo dict
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import asdict, dataclass
from typing import Optional

from honeypots.common.event import HoneypotEvent


# ---------------------------------------------------------------------------
# GeoInfo model
# ---------------------------------------------------------------------------

@dataclass
class GeoInfo:
    """
    Geographic and network metadata for a resolved IP address.

    Attributes:
        ip:           The queried IP address.
        country_code: ISO 3166-1 alpha-2 country code (e.g., 'US', 'DE').
        country_name: Human-readable country name.
        city:         City name, or None if not available.
        latitude:     Approximate latitude, or None.
        longitude:    Approximate longitude, or None.
        asn:          Autonomous System Number (integer), or None.
        org:          Organisation / ASN name, or None.
        is_private:   True if the IP is in an RFC 1918 / loopback range.
        source:       Resolution backend used ('maxminddb' or 'stub').
    """
    ip:           str
    country_code: str
    country_name: str
    city:         Optional[str]   = None
    latitude:     Optional[float] = None
    longitude:    Optional[float] = None
    asn:          Optional[int]   = None
    org:          Optional[str]   = None
    is_private:   bool            = False
    source:       str             = "stub"

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Private IP detection
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
]


def _is_private(ip: str) -> bool:
    """Return True if the IP is in a private/loopback range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Built-in stub resolution table
# ---------------------------------------------------------------------------
# Maps (ip_prefix, max_prefix_len) → GeoInfo fields for well-known ranges.
# First match wins (most-specific prefixes listed first).

_STUB_TABLE: list[tuple[str, GeoInfo]] = [
    # Cloudflare
    ("1.1.1.", GeoInfo(ip="", country_code="AU", country_name="Australia",
                       city="Research", latitude=-37.7, longitude=145.1,
                       asn=13335, org="Cloudflare, Inc.", source="stub")),
    ("1.0.0.", GeoInfo(ip="", country_code="AU", country_name="Australia",
                       city="Research", latitude=-37.7, longitude=145.1,
                       asn=13335, org="Cloudflare, Inc.", source="stub")),
    # Google DNS
    ("8.8.8.", GeoInfo(ip="", country_code="US", country_name="United States",
                       city="Mountain View", latitude=37.4, longitude=-122.1,
                       asn=15169, org="Google LLC", source="stub")),
    ("8.8.4.", GeoInfo(ip="", country_code="US", country_name="United States",
                       city="Mountain View", latitude=37.4, longitude=-122.1,
                       asn=15169, org="Google LLC", source="stub")),
    # AWS us-east-1 sample range
    ("3.80.", GeoInfo(ip="", country_code="US", country_name="United States",
                      city="Ashburn", latitude=39.0, longitude=-77.5,
                      asn=16509, org="Amazon.com, Inc.", source="stub")),
    ("52.0.", GeoInfo(ip="", country_code="US", country_name="United States",
                      city="Ashburn", latitude=39.0, longitude=-77.5,
                      asn=16509, org="Amazon.com, Inc.", source="stub")),
    # Azure
    ("20.0.", GeoInfo(ip="", country_code="US", country_name="United States",
                      city="Des Moines", latitude=41.6, longitude=-93.6,
                      asn=8075, org="Microsoft Corporation", source="stub")),
    # Shodan scanner
    ("198.20.99.", GeoInfo(ip="", country_code="US", country_name="United States",
                           city="Kansas City", latitude=39.1, longitude=-94.6,
                           asn=20473, org="Shodan.io", source="stub")),
    # Censys scanner
    ("162.142.125.", GeoInfo(ip="", country_code="US", country_name="United States",
                              city="Ann Arbor", latitude=42.3, longitude=-83.7,
                              asn=398324, org="Censys, Inc.", source="stub")),
]


def _stub_resolve(ip: str) -> GeoInfo:
    """
    Attempt to resolve an IP using the built-in stub table.

    Falls back to UNKNOWN if no prefix matches.
    """
    if _is_private(ip):
        return GeoInfo(
            ip=ip,
            country_code="--",
            country_name="Private/Reserved",
            is_private=True,
            source="stub",
        )

    for prefix, template in _STUB_TABLE:
        if ip.startswith(prefix):
            return GeoInfo(
                ip=ip,
                country_code=template.country_code,
                country_name=template.country_name,
                city=template.city,
                latitude=template.latitude,
                longitude=template.longitude,
                asn=template.asn,
                org=template.org,
                is_private=False,
                source="stub",
            )

    return GeoInfo(
        ip=ip,
        country_code="??",
        country_name="Unknown",
        source="stub",
    )


# ---------------------------------------------------------------------------
# MaxMind GeoLite2 resolution (optional)
# ---------------------------------------------------------------------------

def _maxmind_resolve(ip: str, db_path: str) -> Optional[GeoInfo]:
    """
    Attempt to resolve an IP using a MaxMind GeoLite2-City database.

    Returns None if the resolution fails for any reason (db not found, IP not
    in database, library not installed).
    """
    try:
        import maxminddb  # type: ignore
    except ImportError:
        return None

    try:
        with maxminddb.open_database(db_path) as reader:
            record = reader.get(ip)

        if record is None:
            return None

        country = record.get("country", {})
        city_rec = record.get("city", {})
        location = record.get("location", {})
        asn_rec  = record.get("autonomous_system_number")
        org_rec  = record.get("autonomous_system_organization")

        return GeoInfo(
            ip=ip,
            country_code=country.get("iso_code", "??"),
            country_name=(country.get("names", {}).get("en") or "Unknown"),
            city=(city_rec.get("names", {}).get("en") if city_rec else None),
            latitude=location.get("latitude"),
            longitude=location.get("longitude"),
            asn=asn_rec,
            org=org_rec,
            is_private=_is_private(ip),
            source="maxminddb",
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_ip(
    ip: str,
    db_path: Optional[str] = None,
) -> GeoInfo:
    """
    Resolve geographic and ASN information for an IP address.

    Tries MaxMind GeoLite2 first if db_path is provided or the environment
    variable MAXMIND_DB_PATH is set. Falls back to the built-in stub table.

    Args:
        ip:       IPv4 or IPv6 address string.
        db_path:  Optional path to a MaxMind GeoLite2-City.mmdb file.
                  If not provided, reads from MAXMIND_DB_PATH env var.

    Returns:
        GeoInfo with available geographic metadata.
    """
    resolved_db_path = db_path or os.environ.get("MAXMIND_DB_PATH")

    if resolved_db_path:
        result = _maxmind_resolve(ip, resolved_db_path)
        if result is not None:
            return result

    return _stub_resolve(ip)


def enrich_event(
    event: HoneypotEvent,
    db_path: Optional[str] = None,
) -> HoneypotEvent:
    """
    Add geo-enrichment metadata to a HoneypotEvent.

    The GeoInfo dict is stored in event.metadata["geo"]. The original event
    is modified in place; a reference to it is also returned for chaining.

    Args:
        event:   HoneypotEvent to enrich.
        db_path: Optional MaxMind database path.

    Returns:
        The same HoneypotEvent with event.metadata["geo"] populated.
    """
    geo = enrich_ip(event.source_ip, db_path=db_path)
    event.metadata["geo"] = geo.to_dict()
    return event


def enrich_batch(
    events: list[HoneypotEvent],
    db_path: Optional[str] = None,
) -> list[HoneypotEvent]:
    """
    Geo-enrich a list of HoneypotEvents.

    Deduplicates IP lookups — each unique IP is resolved only once, and the
    result is reused for all events from that IP.

    Args:
        events:  List of HoneypotEvent objects to enrich.
        db_path: Optional MaxMind database path.

    Returns:
        The same list with metadata["geo"] populated on each event.
    """
    cache: dict[str, dict] = {}
    for event in events:
        if event.source_ip not in cache:
            geo = enrich_ip(event.source_ip, db_path=db_path)
            cache[event.source_ip] = geo.to_dict()
        event.metadata["geo"] = cache[event.source_ip]
    return events
