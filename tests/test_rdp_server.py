"""Tests for the RDP banner observation server."""

import asyncio

import pytest

from honeypots.common.event import HoneypotEvent, ServiceType
from honeypots.rdp.server import (
    DEFAULT_RDP_NEGOTIATION_FAILURE,
    _extract_requested_protocols,
    start_rdp_banner_observer,
)


def test_extract_requested_protocols_parses_ssl_and_hybrid():
    payload = bytes.fromhex("030000130ee000000000000100080003000000")

    protocols = _extract_requested_protocols(payload)

    assert protocols == ["ssl", "hybrid"]


def test_extract_requested_protocols_returns_empty_for_non_matching_payload():
    payload = b"not-an-rdp-negotiation-request"

    protocols = _extract_requested_protocols(payload)

    assert protocols == []


@pytest.mark.asyncio
async def test_rdp_observer_captures_request_and_returns_failure_frame():
    received: list[HoneypotEvent] = []
    server = await start_rdp_banner_observer("127.0.0.1", 0, received.append)
    payload = bytes.fromhex("030000130ee000000000000100080003000000")

    try:
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()

        response = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
    finally:
        server.close()
        await server.wait_closed()

    assert response == DEFAULT_RDP_NEGOTIATION_FAILURE
    assert [event.service for event in received] == [ServiceType.RDP] * len(received)

    stages = [event.metadata["rdp_stage"] for event in received]
    assert stages[:3] == ["connect", "negotiation_request", "negotiation_failure"]
    assert "disconnect" in stages

    negotiation_event = next(event for event in received if event.metadata["rdp_stage"] == "negotiation_request")
    assert negotiation_event.metadata["payload_size"] == len(payload)
    assert negotiation_event.metadata["requested_protocols"] == ["ssl", "hybrid"]
