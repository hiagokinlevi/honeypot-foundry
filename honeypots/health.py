from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI


@dataclass(frozen=True)
class HealthStatus:
    """Simple JSON response schema for honeypot service health."""

    service: str
    uptime_seconds: int
    active_listeners: List[Dict[str, Any]]
    log_forwarder_connected: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "uptime_seconds": self.uptime_seconds,
            "active_listeners": self.active_listeners,
            "log_forwarder_connected": self.log_forwarder_connected,
        }


# Canonical schema reference for docs/integration tooling.
HEALTH_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": [
        "service",
        "uptime_seconds",
        "active_listeners",
        "log_forwarder_connected",
    ],
    "properties": {
        "service": {"type": "string", "example": "http-honeypot"},
        "uptime_seconds": {"type": "integer", "minimum": 0, "example": 42},
        "active_listeners": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["protocol", "bind", "port"],
                "properties": {
                    "protocol": {"type": "string", "example": "http"},
                    "bind": {"type": "string", "example": "0.0.0.0"},
                    "port": {"type": "integer", "example": 8080},
                },
            },
            "example": [{"protocol": "http", "bind": "0.0.0.0", "port": 8080}],
        },
        "log_forwarder_connected": {"type": "boolean", "example": True},
    },
}


def _build_health_payload(
    service_name: str,
    started_at: float,
    listeners_provider: Callable[[], List[Dict[str, Any]]],
    forwarder_connected_provider: Callable[[], bool],
) -> Dict[str, Any]:
    status = HealthStatus(
        service=service_name,
        uptime_seconds=max(0, int(time.time() - started_at)),
        active_listeners=listeners_provider(),
        log_forwarder_connected=bool(forwarder_connected_provider()),
    )
    return status.to_dict()


def register_health_endpoint(
    app: FastAPI,
    *,
    service_name: str,
    started_at: Optional[float] = None,
    listeners_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None,
    forwarder_connected_provider: Optional[Callable[[], bool]] = None,
) -> None:
    """
    Register a lightweight `/health` endpoint on a FastAPI honeypot service.

    Minimal example:

        app = FastAPI()
        start_ts = time.time()
        register_health_endpoint(
            app,
            service_name="http-honeypot",
            started_at=start_ts,
            listeners_provider=lambda: [{"protocol": "http", "bind": "0.0.0.0", "port": 8080}],
            forwarder_connected_provider=lambda: True,
        )

    Response JSON schema fields:
      - service: string
      - uptime_seconds: integer
      - active_listeners: array of {protocol, bind, port}
      - log_forwarder_connected: boolean
    """
    if started_at is None:
        started_at = time.time()

    if listeners_provider is None:
        listeners_provider = lambda: []

    if forwarder_connected_provider is None:
        forwarder_connected_provider = lambda: True

    @app.get("/health", tags=["health"])
    async def health() -> Dict[str, Any]:
        return _build_health_payload(
            service_name=service_name,
            started_at=started_at,
            listeners_provider=listeners_provider,
            forwarder_connected_provider=forwarder_connected_provider,
        )
