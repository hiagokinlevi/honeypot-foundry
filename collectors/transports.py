"""
Live transport backends for forwarding honeypot events to SIEM endpoints.

The formatters in ``collectors.siem_adapter`` stay responsible for producing
Splunk/Elastic/CEF payloads. This module handles the actual delivery using only
the Python standard library so restricted environments can still forward events.
"""
from __future__ import annotations

import base64
import json
import math
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib import request
from urllib.parse import urlsplit

from collectors.siem_adapter import (
    _validate_siem_routing_value,
    to_cef,
    to_elastic_bulk,
    to_splunk_hec,
)
from honeypots.common.event import HoneypotEvent


class EventTransport:
    """Minimal transport interface used by EventWriter."""

    def send(self, event: HoneypotEvent) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Release any transport resources."""


def _validate_http_endpoint(endpoint_url: str, *, transport_name: str) -> None:
    parsed = urlsplit(endpoint_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{transport_name} endpoint must use http or https.")
    if not parsed.netloc:
        raise ValueError(f"{transport_name} endpoint must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            f"{transport_name} endpoint must not embed credentials in the URL."
        )
    if parsed.query:
        raise ValueError(
            f"{transport_name} endpoint must not include URL query parameters."
        )
    if parsed.fragment:
        raise ValueError(f"{transport_name} endpoint must not include a URL fragment.")


def _validate_syslog_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("CEF/syslog port must be an integer between 1 and 65535.")
    if not 1 <= port <= 65535:
        raise ValueError("CEF/syslog port must be between 1 and 65535.")
    return port


def _validate_syslog_endpoint(host: str, *, port: int, protocol: str) -> None:
    if not isinstance(host, str):
        raise ValueError("CEF/syslog host must be a string.")
    if not host or not host.strip():
        raise ValueError("CEF/syslog host must not be empty.")
    if any(ch.isspace() for ch in host):
        raise ValueError("CEF/syslog host must not contain whitespace.")
    _validate_syslog_port(port)
    if protocol not in {"udp", "tcp"}:
        raise ValueError("CEF/syslog protocol must be tcp or udp.")


def _validate_syslog_facility(facility: int) -> int:
    if isinstance(facility, bool) or not isinstance(facility, int):
        raise ValueError("CEF/syslog facility must be an integer between 0 and 23.")
    if not 0 <= facility <= 23:
        raise ValueError("CEF/syslog facility must be between 0 and 23.")
    return facility


def _validate_syslog_metadata(*, app_name: str, facility: int) -> None:
    if not isinstance(app_name, str):
        raise ValueError("CEF/syslog app name must be a string.")
    if not app_name or not app_name.strip():
        raise ValueError("CEF/syslog app name must not be empty.")
    if any(ch.isspace() for ch in app_name):
        raise ValueError("CEF/syslog app name must not contain whitespace.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in app_name):
        raise ValueError("CEF/syslog app name must not contain control characters.")
    _validate_syslog_facility(facility)


def _validate_timeout(timeout_s: float, *, transport_name: str) -> float:
    if isinstance(timeout_s, bool):
        raise ValueError(f"{transport_name} timeout must be a finite positive number.")

    try:
        normalized_timeout = float(timeout_s)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{transport_name} timeout must be a finite positive number."
        ) from exc

    if not math.isfinite(normalized_timeout) or normalized_timeout <= 0:
        raise ValueError(f"{transport_name} timeout must be a finite positive number.")

    return normalized_timeout


def _contains_control_characters(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _validate_non_empty_secret(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    if value != value.strip():
        raise ValueError(f"{field_name} must not start or end with whitespace.")
    if _contains_control_characters(value):
        raise ValueError(f"{field_name} must not contain control characters.")
    return value


def _validate_basic_auth(
    username: str | None,
    password: str | None,
) -> tuple[str | None, str | None]:
    if (username is None) != (password is None):
        raise ValueError("Elastic username and password must be provided together.")
    if username is None:
        return None, None
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Elastic username must not be empty.")
    if username != username.strip():
        raise ValueError("Elastic username must not start or end with whitespace.")
    if ":" in username:
        raise ValueError("Elastic username must not contain ':'.")
    if _contains_control_characters(username):
        raise ValueError("Elastic username must not contain control characters.")
    if not isinstance(password, str) or not password:
        raise ValueError("Elastic password must not be empty.")
    if password != password.strip():
        raise ValueError("Elastic password must not start or end with whitespace.")
    if _contains_control_characters(password):
        raise ValueError("Elastic password must not contain control characters.")
    return username, password


@dataclass(slots=True)
class SplunkHECTransport(EventTransport):
    endpoint_url: str
    token: str
    index: str = "honeypot"
    source: str = "honeypot-foundry"
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        _validate_http_endpoint(self.endpoint_url, transport_name="Splunk HEC")
        self.token = _validate_non_empty_secret(
            self.token,
            field_name="Splunk HEC token",
        )
        self.index = _validate_siem_routing_value(self.index, field_name="Splunk index")
        self.source = _validate_siem_routing_value(self.source, field_name="Splunk source")
        self.timeout_s = _validate_timeout(self.timeout_s, transport_name="Splunk HEC")

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

    def __post_init__(self) -> None:
        _validate_http_endpoint(self.endpoint_url, transport_name="Elastic bulk")
        self.index = _validate_siem_routing_value(self.index, field_name="Elastic index")
        self.username, self.password = _validate_basic_auth(self.username, self.password)
        self.timeout_s = _validate_timeout(self.timeout_s, transport_name="Elastic bulk")

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

    def __post_init__(self) -> None:
        _validate_syslog_endpoint(self.host, port=self.port, protocol=self.protocol)
        _validate_syslog_metadata(app_name=self.app_name, facility=self.facility)
        self.timeout_s = _validate_timeout(self.timeout_s, transport_name="CEF/syslog")

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
