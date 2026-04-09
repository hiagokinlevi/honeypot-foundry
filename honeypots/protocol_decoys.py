"""
Protocol Decoy Handlers
=========================
Simulates MySQL and Redis server handshakes to capture attacker probes,
credential attempts, and command patterns. All handlers are read-only
decoys — no data is persisted, no real service is exposed.

Each handler:
 - Sends a realistic server greeting (matching the real protocol)
 - Records the client's authentication attempt or first command
 - Returns a plausible error response
 - Logs a structured DecoyEvent that feeds into the broader honeypot pipeline

Protocols Supported
--------------------
MySQL 5.7/8.0     TCP handshake: Server Greeting → Client Handshake →
                   Auth Response → Error packet (access denied)

Redis 6.x/7.x     Inline command / RESP protocol: records PING, AUTH,
                   INFO, CONFIG GET, KEYS * probes

Usage::

    from honeypots.protocol_decoys import (
        MySQLDecoy,
        RedisDecoy,
        DecoyEvent,
        DecoyProtocol,
    )

    # In a TCP server loop:
    decoy = MySQLDecoy(source_ip="1.2.3.4", source_port=54321)
    events = decoy.handle(raw_bytes_from_client)
    for event in events:
        print(event.to_dict())
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DecoyProtocol(str, Enum):
    MYSQL = "MYSQL"
    REDIS = "REDIS"


class DecoyEventType(str, Enum):
    CONNECT      = "CONNECT"       # Client connected to decoy
    AUTH_ATTEMPT = "AUTH_ATTEMPT"  # Credential attempt captured
    COMMAND      = "COMMAND"       # Non-auth command captured
    DISCONNECT   = "DISCONNECT"    # Connection closed


# ---------------------------------------------------------------------------
# DecoyEvent
# ---------------------------------------------------------------------------

@dataclass
class DecoyEvent:
    """
    A structured event emitted by a protocol decoy handler.

    Attributes:
        protocol:    Which decoy protocol fired this event.
        event_type:  Type of event.
        source_ip:   Client IP address.
        source_port: Client source port.
        timestamp:   Unix timestamp of the event.
        username:    Captured username (empty if not applicable).
        password:    Captured password/auth token (masked in to_dict()).
        command:     Full command string captured (Redis) or empty.
        detail:      Human-readable detail string.
        raw_bytes:   Raw bytes received (hex-encoded for display).
    """
    protocol:    DecoyProtocol
    event_type:  DecoyEventType
    source_ip:   str
    source_port: int = 0
    timestamp:   float = field(default_factory=time.time)
    username:    str = ""
    password:    str = ""
    command:     str = ""
    detail:      str = ""
    raw_bytes:   bytes = b""

    def password_hash(self) -> str:
        """Return SHA-256 of the password without exposing the plaintext."""
        if not self.password:
            return ""
        return hashlib.sha256(self.password.encode("utf-8", errors="replace")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol":      self.protocol.value,
            "event_type":    self.event_type.value,
            "source_ip":     self.source_ip,
            "source_port":   self.source_port,
            "timestamp":     self.timestamp,
            "username":      self.username,
            "password_hash": self.password_hash(),  # never log plaintext
            "command":       self.command,
            "detail":        self.detail,
            "raw_hex":       self.raw_bytes[:64].hex(),
        }


# ---------------------------------------------------------------------------
# MySQL decoy
# ---------------------------------------------------------------------------

# MySQL error packet constants
_MYSQL_ERR_ACCESS_DENIED = (
    b"\xff"                    # error marker
    b"\x15\x04"                # error code 1045 (access denied) LE
    b"#28000"                  # SQL state marker + SQLSTATE
    b"Access denied for user 'decoy'@'%' (using password: YES)"
)

_MYSQL_OK_PACKET = (
    b"\x00"  # OK marker
    b"\x00"  # affected rows
    b"\x00"  # last insert id
    b"\x02\x00"  # server status
    b"\x00\x00"  # warnings
)

# Realistic MySQL 5.7 server greeting (simplified)
# Packet structure: [len(3)] [seq(1)] [payload]
def _mysql_greeting() -> bytes:
    """Build a realistic MySQL server greeting packet."""
    scramble_1 = os.urandom(8)
    scramble_2 = os.urandom(12)
    payload = (
        b"\x0a"                    # protocol version 10
        + b"5.7.42-log\x00"        # server version
        + b"\x01\x00\x00\x00"      # connection id = 1
        + scramble_1
        + b"\x00"                  # filler
        + b"\xff\xf7"              # capability flags low
        + b"\x21"                  # charset utf8
        + b"\x02\x00"              # server status
        + b"\xff\x81"              # capability flags high
        + b"\x15"                  # auth plugin data length
        + b"\x00" * 10             # reserved
        + scramble_2
        + b"\x00"                  # null terminator
        + b"mysql_native_password\x00"
    )
    length = len(payload).to_bytes(3, "little")
    return length + b"\x00" + payload  # sequence 0


class MySQLDecoy:
    """
    MySQL protocol decoy handler.

    Manages a single client connection lifecycle:
    1. Emit CONNECT event
    2. Generate server greeting (call greeting_bytes())
    3. Parse client handshake (call handle(data))
    4. Return error response bytes and DecoyEvents

    Args:
        source_ip:   Client IP address.
        source_port: Client source port.
        server_version: MySQL version string to advertise (default "5.7.42-log").
    """

    def __init__(
        self,
        source_ip: str,
        source_port: int = 0,
        server_version: str = "5.7.42-log",
    ) -> None:
        self._source_ip    = source_ip
        self._source_port  = source_port
        self._server_ver   = server_version
        self._connected    = False
        self._events: list[DecoyEvent] = []

    def greeting_bytes(self) -> bytes:
        """Return the server greeting bytes to send to the client."""
        self._connected = True
        self._events.append(DecoyEvent(
            protocol=DecoyProtocol.MYSQL,
            event_type=DecoyEventType.CONNECT,
            source_ip=self._source_ip,
            source_port=self._source_port,
            detail=f"MySQL decoy connection from {self._source_ip}",
        ))
        return _mysql_greeting()

    def handle(self, data: bytes) -> tuple[bytes, list[DecoyEvent]]:
        """
        Parse a client handshake/auth packet.

        Args:
            data: Raw bytes received from the client.

        Returns:
            (response_bytes, events) tuple. response_bytes should be sent
            back to the client.
        """
        events: list[DecoyEvent] = []
        if not data:
            return b"", events

        username, password = _parse_mysql_handshake(data)

        event = DecoyEvent(
            protocol=DecoyProtocol.MYSQL,
            event_type=DecoyEventType.AUTH_ATTEMPT,
            source_ip=self._source_ip,
            source_port=self._source_port,
            username=username,
            password=password,
            detail=(
                f"MySQL auth attempt: user='{username}' "
                f"from {self._source_ip}"
            ),
            raw_bytes=data,
        )
        events.append(event)
        self._events.extend(events)

        # Send error response (sequence number 2 = after greeting seq 0, client seq 1)
        err_len = len(_MYSQL_ERR_ACCESS_DENIED).to_bytes(3, "little")
        response = err_len + b"\x02" + _MYSQL_ERR_ACCESS_DENIED
        return response, events

    @property
    def captured_events(self) -> list[DecoyEvent]:
        return list(self._events)


def _parse_mysql_handshake(data: bytes) -> tuple[str, str]:
    """
    Extract username and hashed auth response from a MySQL HandshakeResponse.
    Returns (username, auth_response_hex).
    """
    if len(data) < 36:
        return "", ""
    try:
        # Skip: packet header (4), capability flags (4), max_packet (4), charset (1), reserved (23)
        offset = 4 + 4 + 4 + 1 + 23
        if offset >= len(data):
            return "", ""
        # Username is null-terminated
        end = data.index(b"\x00", offset) if b"\x00" in data[offset:] else len(data)
        username = data[offset:end].decode("utf-8", errors="replace")
        offset = end + 1

        # Auth response: length-prefixed
        if offset >= len(data):
            return username, ""
        auth_len = data[offset]
        offset += 1
        auth_response = data[offset: offset + auth_len].hex()
        return username, auth_response
    except (ValueError, IndexError, UnicodeDecodeError):
        return "", ""


# ---------------------------------------------------------------------------
# Redis decoy
# ---------------------------------------------------------------------------

# RESP protocol constants
_REDIS_PONG       = b"+PONG\r\n"
_REDIS_OK         = b"+OK\r\n"
_REDIS_AUTH_ERR   = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n"
_REDIS_NOAUTH_ERR = b"-NOAUTH Authentication required.\r\n"
_REDIS_ERR_CMD    = b"-ERR unknown command\r\n"

# Commands that suggest reconnaissance / exploitation
_RECON_COMMANDS = frozenset({
    "info", "config", "slaveof", "replicaof",
    "keys", "scan", "debug", "monitor",
    "flushall", "flushdb",
    "save", "bgsave",
    "client", "cluster",
    "acl", "latency",
})


class RedisDecoy:
    """
    Redis protocol decoy handler.

    Parses RESP and inline Redis commands from the client, records
    auth attempts and reconnaissance commands, and returns realistic
    error responses.

    Args:
        source_ip:   Client IP address.
        source_port: Client source port.
        require_auth: If True, return NOAUTH error for commands before AUTH
                      (default True).
    """

    def __init__(
        self,
        source_ip: str,
        source_port: int = 0,
        require_auth: bool = True,
    ) -> None:
        self._source_ip    = source_ip
        self._source_port  = source_port
        self._require_auth = require_auth
        self._authenticated = False
        self._events: list[DecoyEvent] = []
        self._events.append(DecoyEvent(
            protocol=DecoyProtocol.REDIS,
            event_type=DecoyEventType.CONNECT,
            source_ip=source_ip,
            source_port=source_port,
            detail=f"Redis decoy connection from {source_ip}",
        ))

    def handle(self, data: bytes) -> tuple[bytes, list[DecoyEvent]]:
        """
        Parse one or more Redis commands from raw bytes.

        Returns:
            (response_bytes, events) — response_bytes are the combined
            responses for all commands in the data buffer.
        """
        events: list[DecoyEvent] = []
        responses: list[bytes] = []

        commands = _parse_redis_commands(data)
        for cmd_parts in commands:
            if not cmd_parts:
                continue
            cmd_name = cmd_parts[0].upper()
            resp, evts = self._dispatch(cmd_name, cmd_parts, data)
            responses.append(resp)
            events.extend(evts)

        self._events.extend(events)
        return b"".join(responses), events

    def _dispatch(
        self,
        cmd_name: str,
        parts: list[str],
        raw: bytes,
    ) -> tuple[bytes, list[DecoyEvent]]:
        """Dispatch a parsed command to the appropriate handler."""
        if cmd_name == "PING":
            return _REDIS_PONG, []

        if cmd_name == "AUTH":
            return self._handle_auth(parts, raw)

        if cmd_name == "QUIT":
            evt = DecoyEvent(
                protocol=DecoyProtocol.REDIS,
                event_type=DecoyEventType.DISCONNECT,
                source_ip=self._source_ip,
                source_port=self._source_port,
                command="QUIT",
                detail="Client sent QUIT",
            )
            return _REDIS_OK, [evt]

        # Require auth for everything else
        if self._require_auth and not self._authenticated:
            evt = DecoyEvent(
                protocol=DecoyProtocol.REDIS,
                event_type=DecoyEventType.COMMAND,
                source_ip=self._source_ip,
                source_port=self._source_port,
                command=" ".join(parts[:3]),
                detail=f"Unauthenticated command '{cmd_name}' from {self._source_ip}",
                raw_bytes=raw,
            )
            return _REDIS_NOAUTH_ERR, [evt]

        # Log recon commands
        if cmd_name.lower() in _RECON_COMMANDS:
            evt = DecoyEvent(
                protocol=DecoyProtocol.REDIS,
                event_type=DecoyEventType.COMMAND,
                source_ip=self._source_ip,
                source_port=self._source_port,
                command=" ".join(parts[:4]),
                detail=f"Recon command '{cmd_name}' from {self._source_ip}",
                raw_bytes=raw,
            )
            return _REDIS_ERR_CMD, [evt]

        return _REDIS_ERR_CMD, []

    def _handle_auth(self, parts: list[str], raw: bytes) -> tuple[bytes, list[DecoyEvent]]:
        """Handle AUTH command: record credentials, return error."""
        password = parts[1] if len(parts) > 1 else ""
        username = parts[1] if len(parts) > 2 else ""
        if len(parts) > 2:
            # AUTH username password (Redis 6+)
            username = parts[1]
            password = parts[2]

        evt = DecoyEvent(
            protocol=DecoyProtocol.REDIS,
            event_type=DecoyEventType.AUTH_ATTEMPT,
            source_ip=self._source_ip,
            source_port=self._source_port,
            username=username,
            password=password,
            command="AUTH",
            detail=(
                f"Redis AUTH attempt: user='{username}' "
                f"from {self._source_ip}"
            ),
            raw_bytes=raw,
        )
        # Always reject — this is a decoy
        return _REDIS_AUTH_ERR, [evt]

    @property
    def captured_events(self) -> list[DecoyEvent]:
        return list(self._events)


# ---------------------------------------------------------------------------
# Redis command parser
# ---------------------------------------------------------------------------

def _parse_redis_commands(data: bytes) -> list[list[str]]:
    """
    Parse RESP or inline commands from raw bytes.
    Returns a list of command-part lists (each list is one command).
    """
    commands: list[list[str]] = []
    text = data.decode("utf-8", errors="replace")

    # RESP bulk string arrays start with *
    if text.startswith("*"):
        parts = _parse_resp_array(text)
        if parts:
            commands.append(parts)
        return commands

    # Inline commands: split by \r\n
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line:
            commands.append(line.split())

    return commands


def _parse_resp_array(text: str) -> list[str]:
    """
    Parse a single RESP array command.
    Returns list of bulk string values, or empty list on parse error.
    """
    try:
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines or not lines[0].startswith("*"):
            return []
        count = int(lines[0][1:])
        result: list[str] = []
        idx = 1
        for _ in range(count):
            if idx >= len(lines):
                break
            if lines[idx].startswith("$"):
                idx += 1  # skip length
            if idx < len(lines):
                result.append(lines[idx])
                idx += 1
        return result
    except (ValueError, IndexError):
        return []
