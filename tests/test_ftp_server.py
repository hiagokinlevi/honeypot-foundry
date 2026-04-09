"""Tests for the FTP observation server."""

import asyncio

import pytest

from honeypots.common.event import HoneypotEvent, ServiceType
from honeypots.ftp.server import DEFAULT_FTP_BANNER, FTPObservationSession, start_ftp_observation_server


class TestFTPObservationSession:
    def test_welcome_message_emits_connect_event(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)

        banner = session.welcome_message().decode("utf-8")

        assert banner == f"220 {DEFAULT_FTP_BANNER}\r\n"
        assert len(received) == 1
        assert received[0].service == ServiceType.FTP
        assert received[0].metadata["ftp_command"] == "CONNECT"
        assert received[0].metadata["ftp_reply_code"] == 220

    def test_user_command_tracks_username(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()

        response = session.handle_line(b"USER analyst\r\n").decode("utf-8")

        assert response == "331 Password required for analyst.\r\n"
        event = received[-1]
        assert event.username == "analyst"
        assert event.metadata["ftp_command"] == "USER"
        assert event.metadata["auth_stage"] == "username"

    def test_pass_command_masks_password(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()
        session.handle_line(b"USER root\r\n")

        response = session.handle_line(b"PASS hunter2\r\n").decode("utf-8")

        assert response == "530 Login incorrect.\r\n"
        event = received[-1]
        assert event.username == "root"
        assert event.credential_observed is not None
        assert "hunter2" not in event.credential_observed
        assert event.metadata["ftp_command"] == "PASS"
        assert event.metadata["auth_stage"] == "password"

    def test_feat_returns_multiline_response(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()

        response = session.handle_line(b"FEAT\r\n").decode("utf-8")

        assert response.startswith("211-Extensions supported\r\n")
        assert response.endswith("211 End\r\n")
        assert received[-1].metadata["ftp_command"] == "FEAT"

    def test_quit_marks_session_closed(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()

        response = session.handle_line(b"QUIT\r\n").decode("utf-8")

        assert response == "221 Goodbye.\r\n"
        assert session.closed is True
        assert received[-1].metadata["ftp_command"] == "QUIT"

    def test_emit_disconnect_records_duration(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()
        session.emit_disconnect()

        event = received[-1]
        assert event.metadata["ftp_command"] == "DISCONNECT"
        assert event.metadata["session_duration_ms"] >= 0

    def test_unknown_command_returns_500(self):
        received: list[HoneypotEvent] = []
        session = FTPObservationSession("1.2.3.4", 2121, received.append)
        session.welcome_message()

        response = session.handle_line(b"BOGUS test\r\n").decode("utf-8")

        assert response == "500 Syntax error, command unrecognized.\r\n"
        assert received[-1].metadata["ftp_command"] == "BOGUS"
        assert received[-1].metadata["ftp_reply_code"] == 500


@pytest.mark.asyncio
async def test_ftp_server_captures_login_attempt_and_quit():
    received: list[HoneypotEvent] = []
    server = await start_ftp_observation_server("127.0.0.1", 0, received.append)

    try:
        sock = server.sockets[0]
        port = sock.getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        banner = await reader.readline()
        writer.write(b"USER root\r\n")
        await writer.drain()
        user_reply = await reader.readline()

        writer.write(b"PASS toor\r\n")
        await writer.drain()
        pass_reply = await reader.readline()

        writer.write(b"QUIT\r\n")
        await writer.drain()
        quit_reply = await reader.readline()

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
    finally:
        server.close()
        await server.wait_closed()

    assert banner.decode("utf-8") == f"220 {DEFAULT_FTP_BANNER}\r\n"
    assert user_reply.decode("utf-8") == "331 Password required for root.\r\n"
    assert pass_reply.decode("utf-8") == "530 Login incorrect.\r\n"
    assert quit_reply.decode("utf-8") == "221 Goodbye.\r\n"

    commands = [event.metadata["ftp_command"] for event in received]
    assert commands[:4] == ["CONNECT", "USER", "PASS", "QUIT"]
    assert "DISCONNECT" in commands
