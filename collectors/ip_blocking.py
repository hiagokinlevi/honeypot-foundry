from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Protocol

import requests

logger = logging.getLogger(__name__)


class BlockProvider(Protocol):
    """Protocol for block providers."""

    def block_ip(self, ip: str, reason: str = "honeypot_detection") -> bool:
        ...


@dataclass
class IPBlockDecision:
    """Decision result from event evaluation."""

    should_block: bool
    source_ip: Optional[str]
    reason: str


class IPTablesBlockProvider:
    """Block IPs using iptables INPUT chain drop rules."""

    def __init__(self, chain: str = "INPUT") -> None:
        self.chain = chain

    def block_ip(self, ip: str, reason: str = "honeypot_detection") -> bool:
        if not _is_valid_ip(ip):
            logger.warning("iptables block skipped: invalid IP '%s'", ip)
            return False

        check_cmd = ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"]
        add_cmd = ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"]

        try:
            check = subprocess.run(check_cmd, check=False, capture_output=True, text=True)
            if check.returncode == 0:
                logger.debug("iptables rule already present for %s", ip)
                return True

            add = subprocess.run(add_cmd, check=False, capture_output=True, text=True)
            if add.returncode != 0:
                logger.error("iptables add failed for %s: %s", ip, add.stderr.strip())
                return False

            logger.info("Blocked IP via iptables: %s (reason=%s)", ip, reason)
            return True
        except FileNotFoundError:
            logger.error("iptables not found on host")
            return False
        except Exception as exc:  # pragma: no cover
            logger.exception("Unexpected iptables error for %s: %s", ip, exc)
            return False


class CloudflareBlockProvider:
    """Block IPs via Cloudflare firewall ruleset API."""

    def __init__(self, account_id: str, api_token: str, timeout_seconds: int = 10) -> None:
        self.account_id = account_id
        self.api_token = api_token
        self.timeout_seconds = timeout_seconds
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists"

    def block_ip(self, ip: str, reason: str = "honeypot_detection") -> bool:
        if not _is_valid_ip(ip):
            logger.warning("Cloudflare block skipped: invalid IP '%s'", ip)
            return False

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "description": f"honeypot-foundry block: {reason}",
            "kind": "ip",
            "name": "honeypot-foundry-auto-block",
            "items": [{"ip": ip, "comment": reason}],
        }

        try:
            resp = requests.post(self.base_url, headers=headers, json=payload, timeout=self.timeout_seconds)
            if resp.status_code in (200, 201):
                logger.info("Blocked IP via Cloudflare: %s (reason=%s)", ip, reason)
                return True

            logger.error("Cloudflare block failed for %s: status=%s body=%s", ip, resp.status_code, resp.text)
            return False
        except requests.RequestException as exc:
            logger.error("Cloudflare request failed for %s: %s", ip, exc)
            return False


class CrowdSecBlockProvider:
    """Block IPs by creating decisions in CrowdSec Local API."""

    def __init__(self, api_url: str, api_key: str, duration: str = "4h", timeout_seconds: int = 10) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.duration = duration
        self.timeout_seconds = timeout_seconds

    def block_ip(self, ip: str, reason: str = "honeypot_detection") -> bool:
        if not _is_valid_ip(ip):
            logger.warning("CrowdSec block skipped: invalid IP '%s'", ip)
            return False

        endpoint = f"{self.api_url}/v1/decisions"
        headers = {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "duration": self.duration,
            "origin": "honeypot-foundry",
            "reason": reason,
            "scope": "Ip",
            "type": "ban",
            "value": ip,
        }

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=self.timeout_seconds)
            if resp.status_code in (200, 201):
                logger.info("Blocked IP via CrowdSec: %s (reason=%s)", ip, reason)
                return True

            logger.error("CrowdSec block failed for %s: status=%s body=%s", ip, resp.status_code, resp.text)
            return False
        except requests.RequestException as exc:
            logger.error("CrowdSec request failed for %s: %s", ip, exc)
            return False


class IPBlockManager:
    """Evaluate honeypot events and block source IPs through a configured provider."""

    def __init__(self, provider: BlockProvider, min_severity: str = "medium") -> None:
        self.provider = provider
        self.min_severity = min_severity
        self._severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def evaluate_event(self, event: Dict) -> IPBlockDecision:
        src = event.get("source_ip") or event.get("src_ip") or event.get("client_ip")
        if not src:
            return IPBlockDecision(False, None, "missing_source_ip")

        if not _is_valid_ip(src):
            return IPBlockDecision(False, src, "invalid_source_ip")

        severity = str(event.get("severity", "medium")).lower()
        if self._severity_rank.get(severity, 2) < self._severity_rank.get(self.min_severity, 2):
            return IPBlockDecision(False, src, f"severity_below_threshold:{severity}")

        reason = str(event.get("event_type") or event.get("action") or "honeypot_detection")
        return IPBlockDecision(True, src, reason)

    def process_event(self, event: Dict) -> bool:
        decision = self.evaluate_event(event)
        if not decision.should_block or not decision.source_ip:
            logger.debug("IP block not triggered: %s", decision.reason)
            return False

        return self.provider.block_ip(decision.source_ip, decision.reason)


def build_provider_from_env() -> Optional[BlockProvider]:
    """Build optional block provider from environment variables.

    Supported values:
      - HONEYPOT_BLOCK_PROVIDER=iptables
      - HONEYPOT_BLOCK_PROVIDER=cloudflare (+ HONEYPOT_CF_ACCOUNT_ID, HONEYPOT_CF_API_TOKEN)
      - HONEYPOT_BLOCK_PROVIDER=crowdsec (+ HONEYPOT_CROWDSEC_API_URL, HONEYPOT_CROWDSEC_API_KEY)
    """

    provider_name = os.getenv("HONEYPOT_BLOCK_PROVIDER", "").strip().lower()
    if not provider_name:
        return None

    if provider_name == "iptables":
        chain = os.getenv("HONEYPOT_IPTABLES_CHAIN", "INPUT")
        return IPTablesBlockProvider(chain=chain)

    if provider_name == "cloudflare":
        account_id = os.getenv("HONEYPOT_CF_ACCOUNT_ID", "")
        api_token = os.getenv("HONEYPOT_CF_API_TOKEN", "")
        if not account_id or not api_token:
            logger.error("Cloudflare provider selected but credentials are missing")
            return None
        return CloudflareBlockProvider(account_id=account_id, api_token=api_token)

    if provider_name == "crowdsec":
        api_url = os.getenv("HONEYPOT_CROWDSEC_API_URL", "")
        api_key = os.getenv("HONEYPOT_CROWDSEC_API_KEY", "")
        duration = os.getenv("HONEYPOT_CROWDSEC_DURATION", "4h")
        if not api_url or not api_key:
            logger.error("CrowdSec provider selected but API config is missing")
            return None
        return CrowdSecBlockProvider(api_url=api_url, api_key=api_key, duration=duration)

    logger.error("Unsupported HONEYPOT_BLOCK_PROVIDER value: %s", provider_name)
    return None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def block_record(source_ip: str, provider: str, reason: str) -> Dict[str, str]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "provider": provider,
        "reason": reason,
        "event_type": "ip_block",
    }
