"""
API credential decoy server.

Mimics a JSON API with authentication endpoints (/auth/token, /api/keys/validate).
All authentication attempts are observed and logged — access is never granted.
Useful for detecting automated credential stuffing targeting API services.
"""
from __future__ import annotations
from collections.abc import Callable
from typing import Any
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
from honeypots.common.event import HoneypotEvent, ServiceType

# Endpoints that commonly receive automated credential attacks
_CREDENTIAL_ENDPOINTS = {
    "/auth/token",
    "/api/v1/auth",
    "/oauth/token",
    "/api/keys/validate",
    "/v1/authenticate",
    "/login",
    "/signin",
}


def build_api_decoy(event_callback: Callable[[HoneypotEvent], None]) -> FastAPI:
    """
    Build a FastAPI decoy that mimics an authenticated API.

    All credential attempts are observed and logged. The server never grants
    access — authentication responses always indicate failure with plausible
    error messages to sustain attacker engagement for observation.

    Args:
        event_callback: Called for every incoming request.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="API Service",
        version="1.0.0",
        docs_url=None,  # Hide docs to look like a real production API
        redoc_url=None,
    )

    @app.post("/auth/token")
    async def auth_token(request: Request) -> JSONResponse:
        """Observe OAuth-style token requests."""
        body: dict[str, Any] = {}
        try:
            body = await request.json()
        except Exception:
            pass

        _record_api_event(request, "/auth/token", body, event_callback)
        # Return a plausible 401 to sustain observation
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Client authentication failed"},
            status_code=401,
        )

    @app.post("/api/keys/validate")
    async def validate_api_key(
        request: Request,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Observe API key and Bearer token validation attempts."""
        credential = x_api_key or authorization or ""
        _record_api_event(
            request,
            "/api/keys/validate",
            {"credential_header": credential},
            event_callback,
        )
        return JSONResponse({"valid": False, "message": "Invalid API key"}, status_code=401)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def catch_all(request: Request, path: str) -> JSONResponse:
        """Catch-all for all other paths."""
        _record_api_event(request, f"/{path}", {}, event_callback)
        return JSONResponse({"error": "not_found"}, status_code=404)

    return app


def _record_api_event(
    request: Request,
    path: str,
    body: dict[str, Any],
    callback: Callable[[HoneypotEvent], None],
) -> None:
    """Extract request metadata and fire a HoneypotEvent."""
    source_ip = request.client.host if request.client else "unknown"
    source_port = request.client.port if request.client else 0

    # Extract credential hint from body if present (masked automatically by HoneypotEvent)
    credential = (
        body.get("client_secret")
        or body.get("password")
        or body.get("api_key")
        or body.get("credential_header", "")
        or ""
    )

    event = HoneypotEvent(
        service=ServiceType.API,
        source_ip=source_ip,
        source_port=source_port,
        path=path,
        method=request.method,
        user_agent=request.headers.get("user-agent"),
        username=body.get("client_id") or body.get("username"),
        credential_observed=credential or None,
        metadata={
            "is_credential_endpoint": path in _CREDENTIAL_ENDPOINTS,
            "content_type": request.headers.get("content-type", ""),
        },
    )
    callback(event)
