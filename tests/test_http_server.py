import pytest
from httpx import AsyncClient, ASGITransport
from honeypots.http.server import build_http_app
from honeypots.common.event import HoneypotEvent


@pytest.mark.asyncio
async def test_http_server_logs_request():
    received: list[HoneypotEvent] = []
    app = build_http_app(received.append)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/admin")

    assert resp.status_code == 200
    assert len(received) == 1
    assert received[0].path == "/admin"
    assert received[0].method == "GET"


@pytest.mark.asyncio
async def test_http_server_catches_all_paths():
    received: list[HoneypotEvent] = []
    app = build_http_app(received.append)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/login", json={"user": "x", "pass": "y"})
        await client.get("/robots.txt")

    assert len(received) == 2
