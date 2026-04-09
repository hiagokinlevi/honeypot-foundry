"""
FTP observation server.

Implements a low-interaction FTP decoy that records username/password
attempts and common reconnaissance commands without ever exposing a real
filesystem or granting authentication.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from uuid import uuid4

from honeypots.common.event import HoneypotEvent, ServiceType


DEFAULT_FTP_BANNER = "Microsoft FTP Service"

_MULTILINE_FEAT_RESPONSE = (
    b"211-Extensions supported\r\n"
    b" UTF8\r\n"
    b" AUTH TLS\r\n"
    b"211 End\r\n"
)


def _format_reply(code: int, message: str) -> bytes:
    """Return a single-line FTP reply terminated with CRLF."""
    return f"{code} {message}\r\n".encode("utf-8")


def _parse_command(line: bytes) -> tuple[str, str]:
    """Extract an FTP command and its argument from a raw line."""
    text = line.decode("utf-8", errors="replace").strip()
    if not text:
        return "", ""

    command, _, argument = text.partition(" ")
    return command.upper(), argument.strip()


class FTPObservationSession:
    """
    Maintain the state for a single FTP decoy connection.

    The session is intentionally small and deterministic so it can be unit
    tested without opening real sockets.
    """

    def __init__(
        self,
        source_ip: str,
        source_port: int,
        event_callback: Callable[[HoneypotEvent], None],
        banner: str = DEFAULT_FTP_BANNER,
    ) -> None:
        self._source_ip = source_ip
        self._source_port = source_port
        self._event_callback = event_callback
        self._banner = banner
        self._session_id = uuid4().hex[:12]
        self._username: str | None = None
        self._command_count = 0
        self._closed = False
        self._started_at = datetime.now(timezone.utc)

    @property
    def closed(self) -> bool:
        """Whether the session should be terminated by the caller."""
        return self._closed

    def welcome_message(self) -> bytes:
        """Emit the connect event and return the banner presented to the client."""
        self._emit_event(
            ftp_command="CONNECT",
            ftp_reply_code=220,
            ftp_reply_message=self._banner,
        )
        return _format_reply(220, self._banner)

    def handle_line(self, line: bytes) -> bytes:
        """Process a raw FTP command line and return the decoy response bytes."""
        command, argument = _parse_command(line)
        self._command_count += 1

        if not command:
            self._emit_event(
                ftp_command="EMPTY",
                ftp_reply_code=500,
                ftp_reply_message="Syntax error, command unrecognized.",
            )
            return _format_reply(500, "Syntax error, command unrecognized.")

        if command == "USER":
            self._username = argument or "anonymous"
            self._emit_event(
                ftp_command="USER",
                ftp_reply_code=331,
                ftp_reply_message=f"Password required for {self._username}.",
                username=self._username,
                ftp_argument=argument,
                auth_stage="username",
            )
            return _format_reply(331, f"Password required for {self._username}.")

        if command == "PASS":
            username = self._username or "anonymous"
            self._emit_event(
                ftp_command="PASS",
                ftp_reply_code=530,
                ftp_reply_message="Login incorrect.",
                username=username,
                credential_observed=argument or None,
                ftp_argument_length=len(argument),
                auth_stage="password",
            )
            return _format_reply(530, "Login incorrect.")

        if command == "SYST":
            self._emit_event(
                ftp_command="SYST",
                ftp_reply_code=215,
                ftp_reply_message="UNIX Type: L8",
            )
            return _format_reply(215, "UNIX Type: L8")

        if command == "FEAT":
            self._emit_event(
                ftp_command="FEAT",
                ftp_reply_code=211,
                ftp_reply_message="Extensions supported",
            )
            return _MULTILINE_FEAT_RESPONSE

        if command == "PWD":
            self._emit_event(
                ftp_command="PWD",
                ftp_reply_code=257,
                ftp_reply_message='"/" is current directory.',
            )
            return _format_reply(257, '"/" is current directory.')

        if command == "TYPE":
            mode = argument.upper() or "A"
            self._emit_event(
                ftp_command="TYPE",
                ftp_reply_code=200,
                ftp_reply_message=f"Type set to {mode}.",
                ftp_argument=argument,
            )
            return _format_reply(200, f"Type set to {mode}.")

        if command == "NOOP":
            self._emit_event(
                ftp_command="NOOP",
                ftp_reply_code=200,
                ftp_reply_message="NOOP ok.",
            )
            return _format_reply(200, "NOOP ok.")

        if command == "PASV":
            self._emit_event(
                ftp_command="PASV",
                ftp_reply_code=425,
                ftp_reply_message="Can't open data connection.",
            )
            return _format_reply(425, "Can't open data connection.")

        if command in {"LIST", "RETR", "STOR", "CWD", "SIZE", "MDTM"}:
            self._emit_event(
                ftp_command=command,
                ftp_reply_code=550,
                ftp_reply_message="Requested action not taken.",
                ftp_argument=argument,
            )
            return _format_reply(550, "Requested action not taken.")

        if command == "QUIT":
            self._closed = True
            self._emit_event(
                ftp_command="QUIT",
                ftp_reply_code=221,
                ftp_reply_message="Goodbye.",
            )
            return _format_reply(221, "Goodbye.")

        self._emit_event(
            ftp_command=command,
            ftp_reply_code=500,
            ftp_reply_message="Syntax error, command unrecognized.",
            ftp_argument=argument,
        )
        return _format_reply(500, "Syntax error, command unrecognized.")

    def emit_disconnect(self) -> None:
        """Record a disconnect marker for correlation and duration tracking."""
        duration_ms = int((datetime.now(timezone.utc) - self._started_at).total_seconds() * 1000)
        self._emit_event(
            ftp_command="DISCONNECT",
            ftp_reply_code=221 if self._closed else 426,
            ftp_reply_message="Session closed.",
            session_duration_ms=duration_ms,
        )

    def _emit_event(
        self,
        *,
        ftp_command: str,
        ftp_reply_code: int,
        ftp_reply_message: str,
        username: str | None = None,
        credential_observed: str | None = None,
        **metadata: object,
    ) -> None:
        """Build a HoneypotEvent and pass it to the configured callback."""
        event = HoneypotEvent(
            service=ServiceType.FTP,
            source_ip=self._source_ip,
            source_port=self._source_port,
            username=username or self._username,
            credential_observed=credential_observed,
            metadata={
                "session_id": self._session_id,
                "ftp_command": ftp_command,
                "ftp_reply_code": ftp_reply_code,
                "ftp_reply_message": ftp_reply_message,
                "command_count": self._command_count,
                **metadata,
            },
        )
        self._event_callback(event)


async def start_ftp_observation_server(
    host: str,
    port: int,
    event_callback: Callable[[HoneypotEvent], None],
    *,
    banner: str = DEFAULT_FTP_BANNER,
    response_delay_ms: int = 0,
) -> asyncio.AbstractServer:
    """
    Start the FTP observation server.

    Args:
        host: Bind address.
        port: TCP port to listen on.
        event_callback: Called for each structured FTP event.
        banner: Greeting banner sent on connect.
        response_delay_ms: Optional delay before replies to look less synthetic.

    Returns:
        The running asyncio server instance.
    """

    async def _handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername", ("unknown", 0))
        source_ip = peer[0] if isinstance(peer, tuple) and peer else "unknown"
        source_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else 0
        session = FTPObservationSession(
            source_ip=source_ip,
            source_port=source_port,
            event_callback=event_callback,
            banner=banner,
        )

        try:
            writer.write(session.welcome_message())
            await writer.drain()

            while not session.closed:
                line = await reader.readline()
                if not line:
                    break
                if response_delay_ms > 0:
                    await asyncio.sleep(response_delay_ms / 1000)
                writer.write(session.handle_line(line))
                await writer.drain()
        finally:
            session.emit_disconnect()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    return await asyncio.start_server(_handle_client, host=host, port=port)
