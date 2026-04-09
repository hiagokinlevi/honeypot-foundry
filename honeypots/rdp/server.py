"""
RDP banner observation server.

This module implements a low-interaction TCP listener that captures RDP
negotiation attempts, logs source telemetry, and always replies with a safe
negotiation failure frame. No real desktop session is ever exposed.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from uuid import uuid4

from honeypots.common.event import HoneypotEvent, ServiceType


DEFAULT_RDP_NEGOTIATION_FAILURE = bytes.fromhex("030000130ed000001234000302000000")

_RDP_PROTOCOL_MASKS: tuple[tuple[int, str], ...] = (
    (0x00000001, "ssl"),
    (0x00000002, "hybrid"),
    (0x00000004, "rdstls"),
    (0x00000008, "hybrid_ex"),
)


def _extract_requested_protocols(payload: bytes) -> list[str]:
    """
    Parse requested RDP security protocols from a negotiation request payload.

    The function searches for the RDP Negotiation Request marker:
      type=0x01, flags=0x00, length=0x0008 (little-endian).
    """
    marker = b"\x01\x00\x08\x00"
    marker_index = payload.find(marker)
    if marker_index == -1:
        return []

    value_start = marker_index + len(marker)
    if len(payload) < value_start + 4:
        return []

    requested_mask = int.from_bytes(payload[value_start:value_start + 4], "little")
    protocols = [name for bit, name in _RDP_PROTOCOL_MASKS if requested_mask & bit]

    if not protocols and requested_mask != 0:
        protocols.append(f"unknown_mask:0x{requested_mask:08x}")

    return protocols


def _payload_preview(payload: bytes, max_bytes: int = 32) -> str:
    """Return a bounded hex preview of the raw packet payload."""
    return payload[:max_bytes].hex()


async def start_rdp_banner_observer(
    host: str,
    port: int,
    event_callback: Callable[[HoneypotEvent], None],
    *,
    read_timeout_s: float = 2.0,
    response_delay_ms: int = 0,
) -> asyncio.AbstractServer:
    """
    Start a low-interaction RDP negotiation observer.

    Args:
        host: TCP bind address.
        port: TCP port.
        event_callback: Receives all structured telemetry events.
        read_timeout_s: Maximum read timeout for the initial negotiation packet.
        response_delay_ms: Optional delay before the synthetic failure response.
    """

    async def _handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        source_ip = str(peer[0])
        source_port = int(peer[1])
        session_id = uuid4().hex[:12]
        started_at = datetime.now(timezone.utc)

        event_callback(
            HoneypotEvent(
                service=ServiceType.RDP,
                source_ip=source_ip,
                source_port=source_port,
                metadata={
                    "rdp_stage": "connect",
                    "session_id": session_id,
                },
            )
        )

        payload = b""
        with suppress(asyncio.TimeoutError):
            payload = await asyncio.wait_for(reader.read(4096), timeout=read_timeout_s)

        if payload:
            requested_protocols = _extract_requested_protocols(payload)
            event_callback(
                HoneypotEvent(
                    service=ServiceType.RDP,
                    source_ip=source_ip,
                    source_port=source_port,
                    metadata={
                        "rdp_stage": "negotiation_request",
                        "session_id": session_id,
                        "payload_size": len(payload),
                        "payload_preview_hex": _payload_preview(payload),
                        "requested_protocols": requested_protocols,
                    },
                )
            )
        else:
            event_callback(
                HoneypotEvent(
                    service=ServiceType.RDP,
                    source_ip=source_ip,
                    source_port=source_port,
                    metadata={
                        "rdp_stage": "no_payload",
                        "session_id": session_id,
                    },
                )
            )

        if response_delay_ms > 0:
            await asyncio.sleep(response_delay_ms / 1000)

        writer.write(DEFAULT_RDP_NEGOTIATION_FAILURE)
        await writer.drain()

        event_callback(
            HoneypotEvent(
                service=ServiceType.RDP,
                source_ip=source_ip,
                source_port=source_port,
                metadata={
                    "rdp_stage": "negotiation_failure",
                    "session_id": session_id,
                    "response_hex": DEFAULT_RDP_NEGOTIATION_FAILURE.hex(),
                },
            )
        )

        writer.close()
        with suppress(Exception):
            await writer.wait_closed()

        duration_ms = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
        event_callback(
            HoneypotEvent(
                service=ServiceType.RDP,
                source_ip=source_ip,
                source_port=source_port,
                metadata={
                    "rdp_stage": "disconnect",
                    "session_id": session_id,
                    "session_duration_ms": duration_ms,
                },
            )
        )

    return await asyncio.start_server(_handle_client, host=host, port=port)
