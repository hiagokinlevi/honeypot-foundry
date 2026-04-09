"""Tests for the API credential decoy server."""
import pytest
from httpx import AsyncClient, ASGITransport
from honeypots.api.server import build_api_decoy
from honeypots.common.event import HoneypotEvent, ServiceType


@pytest.mark.asyncio
async def test_auth_token_observed_and_denied():
    """POST to /auth/token must be logged and return 401."""
    received: list[HoneypotEvent] = []
    app = build_api_decoy(received.append)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/auth/token",
            json={"client_id": "app1", "client_secret": "supersecret", "grant_type": "client_credentials"},
        )

    assert resp.status_code == 401
    assert len(received) == 1
    event = received[0]
    assert event.service == ServiceType.API
    assert event.path == "/auth/token"
    # Credential must be masked — raw secret must not appear
    assert event.credential_observed is not None
    assert "supersecret" not in event.credential_observed
    assert event.credential_observed.startswith("[masked:")


@pytest.mark.asyncio
async def test_api_key_validate_observed():
    """X-Api-Key header attempt is captured."""
    received: list[HoneypotEvent] = []
    app = build_api_decoy(received.append)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/keys/validate", headers={"X-Api-Key": "secret-key-123"})

    assert resp.status_code == 401
    assert len(received) == 1


@pytest.mark.asyncio
async def test_catch_all_returns_404():
    """Unknown paths return 404 and are still logged."""
    received: list[HoneypotEvent] = []
    app = build_api_decoy(received.append)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/unknown/path")

    assert resp.status_code == 404
    assert len(received) == 1
