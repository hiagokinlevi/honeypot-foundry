"""
HTTP observation server.

A FastAPI application that accepts any HTTP request, logs the request
metadata (path, method, headers, source IP) and returns a generic 200 OK.
Used to observe web scanning and credential stuffing behavior.
"""
from __future__ import annotations
from collections.abc import Callable
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from honeypots.common.event import HoneypotEvent, ServiceType

# Common credential submission paths observed in the wild — used to label events
OBSERVED_CREDENTIAL_PATHS = {
    "/login", "/signin", "/auth", "/api/login", "/api/auth",
    "/wp-login.php", "/admin", "/administrator", "/xmlrpc.php",
}


def build_http_app(event_callback: Callable[[HoneypotEvent], None]) -> FastAPI:
    """
    Build and return the FastAPI observation application.

    Args:
        event_callback: Called for every incoming HTTP request.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(title="HTTP Observation Server", docs_url=None, redoc_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def catch_all(request: Request, path: str) -> JSONResponse:
        """Catch-all handler — logs every request and returns a generic response."""
        source_ip = request.client.host if request.client else "unknown"
        source_port = request.client.port if request.client else 0

        event = HoneypotEvent(
            service=ServiceType.HTTP,
            source_ip=source_ip,
            source_port=source_port,
            path=f"/{path}",
            method=request.method,
            user_agent=request.headers.get("user-agent"),
            metadata={
                "is_credential_path": f"/{path}" in OBSERVED_CREDENTIAL_PATHS,
                "content_type": request.headers.get("content-type", ""),
            },
        )
        event_callback(event)
        return JSONResponse({"status": "ok"}, status_code=200)

    return app
