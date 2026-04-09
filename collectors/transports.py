"""
Live transport backends for forwarding honeypot events to SIEM endpoints.

The formatters in ``collectors.siem_adapter`` stay responsible for producing
Splunk/Elastic/CEF payloads. This module handles the actual delivery using only
the Python standard library so restricted environments can still forward events.
"""
from __future__ import annotations

import base64
import json
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib import request

from collectors.siem_adapter import to_cef, to_elastic_bulk, to_splunk_hec
from honeypots.common.event import HoneypotEvent


class EventTransport:
    """Minimal transport interface used by EventWriter."""

    def send(self, event: HoneypotEvent) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Release any transport resources."""


@dataclass(slots=True)
class SplunkHECTransport(EventTransport):
    endpoint_url: str
    token: str
    index: str = "honeypot"
    source: str = "honeypot-foundry"
    timeout_s: float = 5.0

    def send(self, event: HoneypotEvent) -> None:
        payload = json.dumps(
            to_splunk_hec(event, index=self.index, source=self.source)
        ).encode("utf-8")
        req = request.Request(
            self.endpoint_url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
        )
        with request.urlopen(req, timeout=self.timeout_s):
            return


@dataclass(slots=True)
class ElasticBulkTransport(EventTransport):
    endpoint_url: str
    index: str = "honeypot-events"
    username: str | None = None
    password: str | None = None
    timeout_s: float = 5.0

    def send(self, event: HoneypotEvent) -> None:
        payload = to_elastic_bulk(event, index=self.index).encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson"}
        if self.username is not None and self.password is not None:
            basic = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {basic}"
        req = request.Request(
            self.endpoint_url,
            data=payload,
            method="POST",
            headers=headers,
        )
        with request.urlopen(req, timeout=self.timeout_s):
            return


@dataclass(slots=True)
class CEFSyslogTransport(EventTransport):
    host: str
    port: int = 514
    protocol: str = "udp"
    app_name: str = "honeypot-foundry"
    facility: int = 20  # local4
    timeout_s: float = 5.0

    def send(self, event: HoneypotEvent) -> None:
        cef_payload = to_cef(event)
        syslog_message = self._build_syslog_message(cef_payload)
        data = syslog_message.encode("utf-8")
        if self.protocol == "tcp":
            with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
                sock.sendall(data + b"\n")
            return

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_socket.settimeout(self.timeout_s)
            udp_socket.sendto(data, (self.host, self.port))
        finally:
            udp_socket.close()

    def _build_syslog_message(self, cef_payload: str) -> str:
        severity = 6  # informational
        pri = self.facility * 8 + severity
        timestamp = datetime.now(UTC).strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        return f"<{pri}>{timestamp} {hostname} {self.app_name}: {cef_payload}"
