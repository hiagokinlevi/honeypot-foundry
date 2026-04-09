"""
Tests for honeypots/protocol_decoys.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from honeypots.protocol_decoys import (
    DecoyEvent,
    DecoyEventType,
    DecoyProtocol,
    MySQLDecoy,
    RedisDecoy,
    _parse_mysql_handshake,
    _parse_redis_commands,
    _parse_resp_array,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _mysql_client_handshake(username: str = "root", auth_len: int = 20) -> bytes:
    """
    Build a minimal MySQL HandshakeResponse41 packet.
    Layout after 4-byte header:
      capability flags (4) + max packet (4) + charset (1) + reserved (23)
      + username (null-terminated) + auth_len (1) + auth_data (auth_len)
    """
    payload = (
        b"\x85\xa6\x3f\x00"    # capability flags
        + b"\x00\x00\x00\x01"  # max packet size
        + b"\x21"               # charset utf8
        + b"\x00" * 23          # reserved
        + username.encode("utf-8") + b"\x00"
        + bytes([auth_len])
        + b"\xaa" * auth_len
    )
    header = len(payload).to_bytes(3, "little") + b"\x01"  # seq=1
    return header + payload


# ===========================================================================
# DecoyEvent
# ===========================================================================

class TestDecoyEvent:
    def _event(self, password: str = "secret") -> DecoyEvent:
        return DecoyEvent(
            protocol=DecoyProtocol.MYSQL,
            event_type=DecoyEventType.AUTH_ATTEMPT,
            source_ip="10.0.0.1",
            password=password,
        )

    def test_password_not_in_to_dict(self):
        d = self._event().to_dict()
        assert "password" not in d

    def test_password_hash_present(self):
        d = self._event().to_dict()
        assert "password_hash" in d
        assert len(d["password_hash"]) == 16

    def test_empty_password_hash_is_empty_string(self):
        e = DecoyEvent(
            protocol=DecoyProtocol.REDIS,
            event_type=DecoyEventType.CONNECT,
            source_ip="1.2.3.4",
        )
        assert e.password_hash() == ""
        assert e.to_dict()["password_hash"] == ""

    def test_raw_bytes_hex_truncated_to_64(self):
        e = DecoyEvent(
            protocol=DecoyProtocol.MYSQL,
            event_type=DecoyEventType.CONNECT,
            source_ip="1.2.3.4",
            raw_bytes=b"\xff" * 200,
        )
        d = e.to_dict()
        assert len(d["raw_hex"]) == 128  # 64 bytes × 2 hex chars

    def test_to_dict_has_required_keys(self):
        d = self._event().to_dict()
        for k in ("protocol", "event_type", "source_ip", "source_port",
                  "timestamp", "username", "password_hash", "command",
                  "detail", "raw_hex"):
            assert k in d

    def test_protocol_serialized_as_string(self):
        assert self._event().to_dict()["protocol"] == "MYSQL"

    def test_event_type_serialized_as_string(self):
        assert self._event().to_dict()["event_type"] == "AUTH_ATTEMPT"

    def test_different_passwords_produce_different_hashes(self):
        h1 = self._event("password1").password_hash()
        h2 = self._event("password2").password_hash()
        assert h1 != h2

    def test_same_password_produces_same_hash(self):
        h1 = self._event("stable").password_hash()
        h2 = self._event("stable").password_hash()
        assert h1 == h2


# ===========================================================================
# _parse_mysql_handshake
# ===========================================================================

class TestParseMySQLHandshake:
    def test_extracts_username(self):
        data = _mysql_client_handshake(username="admin")
        username, _ = _parse_mysql_handshake(data)
        assert username == "admin"

    def test_extracts_auth_response_hex(self):
        data = _mysql_client_handshake(username="root", auth_len=20)
        _, auth = _parse_mysql_handshake(data)
        assert auth == "aa" * 20

    def test_empty_data_returns_empty(self):
        username, auth = _parse_mysql_handshake(b"")
        assert username == ""
        assert auth == ""

    def test_too_short_returns_empty(self):
        username, auth = _parse_mysql_handshake(b"\x00" * 10)
        assert username == ""
        assert auth == ""

    def test_zero_auth_len(self):
        data = _mysql_client_handshake(username="nopass", auth_len=0)
        username, auth = _parse_mysql_handshake(data)
        assert username == "nopass"
        assert auth == ""


# ===========================================================================
# MySQLDecoy
# ===========================================================================

class TestMySQLDecoyGreeting:
    def test_greeting_bytes_returns_bytes(self):
        d = MySQLDecoy(source_ip="1.2.3.4")
        greeting = d.greeting_bytes()
        assert isinstance(greeting, bytes)
        assert len(greeting) > 10

    def test_greeting_starts_with_protocol_10(self):
        d = MySQLDecoy(source_ip="1.2.3.4")
        greeting = d.greeting_bytes()
        # payload starts at offset 4 (3-byte len + 1-byte seq)
        assert greeting[4] == 0x0a  # protocol version 10

    def test_greeting_emits_connect_event(self):
        d = MySQLDecoy(source_ip="1.2.3.4", source_port=54321)
        d.greeting_bytes()
        events = d.captured_events
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.CONNECT
        assert events[0].source_ip == "1.2.3.4"

    def test_greeting_is_different_each_call(self):
        # scramble bytes should be random
        d1 = MySQLDecoy(source_ip="1.2.3.4")
        d2 = MySQLDecoy(source_ip="1.2.3.4")
        assert d1.greeting_bytes() != d2.greeting_bytes()


class TestMySQLDecoyHandle:
    def _decoy_with_greeting(self, ip="10.0.0.2", port=12345) -> MySQLDecoy:
        d = MySQLDecoy(source_ip=ip, source_port=port)
        d.greeting_bytes()
        return d

    def test_handle_returns_error_packet(self):
        d = self._decoy_with_greeting()
        data = _mysql_client_handshake("root")
        response, events = d.handle(data)
        # Error packet payload starts with 0xff
        assert b"\xff" in response

    def test_handle_emits_auth_attempt_event(self):
        d = self._decoy_with_greeting()
        data = _mysql_client_handshake("root")
        response, events = d.handle(data)
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.AUTH_ATTEMPT

    def test_handle_captures_username(self):
        d = self._decoy_with_greeting()
        data = _mysql_client_handshake("dbadmin")
        response, events = d.handle(data)
        assert events[0].username == "dbadmin"

    def test_handle_captures_auth_response(self):
        d = self._decoy_with_greeting()
        data = _mysql_client_handshake("root", auth_len=20)
        response, events = d.handle(data)
        assert events[0].password != ""
        assert len(events[0].password) == 40  # 20 bytes hex = 40 chars

    def test_handle_empty_data_returns_empty_response(self):
        d = self._decoy_with_greeting()
        response, events = d.handle(b"")
        assert response == b""
        assert events == []

    def test_captured_events_includes_connect_and_auth(self):
        d = self._decoy_with_greeting()
        d.handle(_mysql_client_handshake("root"))
        all_events = d.captured_events
        assert len(all_events) == 2
        assert all_events[0].event_type == DecoyEventType.CONNECT
        assert all_events[1].event_type == DecoyEventType.AUTH_ATTEMPT

    def test_response_contains_access_denied(self):
        d = self._decoy_with_greeting()
        response, _ = d.handle(_mysql_client_handshake("root"))
        assert b"Access denied" in response

    def test_source_ip_in_event(self):
        d = MySQLDecoy(source_ip="192.168.1.50", source_port=9999)
        d.greeting_bytes()
        _, events = d.handle(_mysql_client_handshake("root"))
        assert events[0].source_ip == "192.168.1.50"
        assert events[0].source_port == 9999


# ===========================================================================
# _parse_redis_commands
# ===========================================================================

class TestParseRedisCommands:
    def test_inline_single_command(self):
        result = _parse_redis_commands(b"PING\r\n")
        assert result == [["PING"]]

    def test_inline_command_with_args(self):
        result = _parse_redis_commands(b"AUTH mypassword\r\n")
        assert result == [["AUTH", "mypassword"]]

    def test_inline_multiple_commands(self):
        result = _parse_redis_commands(b"PING\r\nINFO\r\n")
        assert len(result) == 2
        assert result[0] == ["PING"]
        assert result[1] == ["INFO"]

    def test_resp_array_ping(self):
        data = b"*1\r\n$4\r\nPING\r\n"
        result = _parse_redis_commands(data)
        assert result == [["PING"]]

    def test_resp_array_auth(self):
        data = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
        result = _parse_redis_commands(data)
        assert result == [["AUTH", "password"]]

    def test_resp_array_auth_with_username(self):
        data = b"*3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$4\r\npass\r\n"
        result = _parse_redis_commands(data)
        assert result == [["AUTH", "user", "pass"]]

    def test_empty_data_returns_empty(self):
        result = _parse_redis_commands(b"")
        assert result == []

    def test_resp_keys_command(self):
        data = b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n"
        result = _parse_redis_commands(data)
        assert result[0][0] == "KEYS"


class TestParseRespArray:
    def test_simple_ping(self):
        assert _parse_resp_array("*1\r\n$4\r\nPING\r\n") == ["PING"]

    def test_auth_with_password(self):
        result = _parse_resp_array("*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n")
        assert result == ["AUTH", "secret"]

    def test_empty_array(self):
        result = _parse_resp_array("*0\r\n")
        assert result == []

    def test_invalid_returns_empty(self):
        assert _parse_resp_array("not resp") == []

    def test_malformed_count_returns_empty(self):
        assert _parse_resp_array("*abc\r\n") == []


# ===========================================================================
# RedisDecoy — CONNECT event
# ===========================================================================

class TestRedisDecoyConnect:
    def test_connect_event_emitted_on_init(self):
        d = RedisDecoy(source_ip="10.1.2.3", source_port=6380)
        events = d.captured_events
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.CONNECT
        assert events[0].source_ip == "10.1.2.3"
        assert events[0].protocol == DecoyProtocol.REDIS


# ===========================================================================
# RedisDecoy — PING
# ===========================================================================

class TestRedisDecoyPing:
    def test_ping_returns_pong(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, events = d.handle(b"PING\r\n")
        assert b"PONG" in resp

    def test_ping_emits_no_event(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        _, events = d.handle(b"PING\r\n")
        assert events == []

    def test_resp_ping_returns_pong(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, _ = d.handle(b"*1\r\n$4\r\nPING\r\n")
        assert b"PONG" in resp


# ===========================================================================
# RedisDecoy — AUTH
# ===========================================================================

class TestRedisDecoyAuth:
    def test_auth_returns_error(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, events = d.handle(b"AUTH wrongpassword\r\n")
        assert b"WRONGPASS" in resp or b"ERR" in resp or resp.startswith(b"-")

    def test_auth_emits_auth_attempt_event(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        _, events = d.handle(b"AUTH wrongpassword\r\n")
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.AUTH_ATTEMPT

    def test_auth_captures_password(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        _, events = d.handle(b"AUTH mysecretpw\r\n")
        assert events[0].password == "mysecretpw"

    def test_auth_username_password_redis6(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        data = b"*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$8\r\npassword\r\n"
        _, events = d.handle(data)
        assert events[0].username == "admin"
        assert events[0].password == "password"

    def test_auth_event_has_source_ip(self):
        d = RedisDecoy(source_ip="172.16.0.1", source_port=7379)
        _, events = d.handle(b"AUTH test\r\n")
        assert events[0].source_ip == "172.16.0.1"
        assert events[0].source_port == 7379

    def test_auth_password_not_in_to_dict(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        _, events = d.handle(b"AUTH supersecret\r\n")
        d_dict = events[0].to_dict()
        assert "password" not in d_dict
        assert d_dict["password_hash"] != ""

    def test_auth_always_rejected(self):
        # Even if the password is "correct", decoy always rejects
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, _ = d.handle(b"AUTH anypassword\r\n")
        # Response should be an error, not +OK
        assert not resp.startswith(b"+OK")


# ===========================================================================
# RedisDecoy — QUIT
# ===========================================================================

class TestRedisDecoyQuit:
    def test_quit_returns_ok(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, _ = d.handle(b"QUIT\r\n")
        assert b"OK" in resp

    def test_quit_emits_disconnect_event(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        _, events = d.handle(b"QUIT\r\n")
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.DISCONNECT


# ===========================================================================
# RedisDecoy — Unauthenticated commands
# ===========================================================================

class TestRedisDecoyRequireAuth:
    def test_info_before_auth_returns_noauth(self):
        d = RedisDecoy(source_ip="1.2.3.4", require_auth=True)
        resp, _ = d.handle(b"INFO\r\n")
        assert b"NOAUTH" in resp

    def test_keys_before_auth_returns_noauth(self):
        d = RedisDecoy(source_ip="1.2.3.4", require_auth=True)
        resp, _ = d.handle(b"KEYS *\r\n")
        assert b"NOAUTH" in resp

    def test_unauthenticated_command_emits_event(self):
        d = RedisDecoy(source_ip="1.2.3.4", require_auth=True)
        _, events = d.handle(b"CONFIG GET maxmemory\r\n")
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.COMMAND

    def test_no_auth_required_allows_commands(self):
        d = RedisDecoy(source_ip="1.2.3.4", require_auth=False)
        resp, _ = d.handle(b"INFO\r\n")
        # Should NOT return NOAUTH — goes to recon handler
        assert b"NOAUTH" not in resp


# ===========================================================================
# RedisDecoy — Recon commands
# ===========================================================================

class TestRedisDecoyReconCommands:
    def _authenticated_decoy(self) -> RedisDecoy:
        return RedisDecoy(source_ip="5.6.7.8", require_auth=False)

    def test_config_get_logged(self):
        d = self._authenticated_decoy()
        _, events = d.handle(b"CONFIG GET maxmemory\r\n")
        assert any(e.event_type == DecoyEventType.COMMAND for e in events)

    def test_flushall_logged(self):
        d = self._authenticated_decoy()
        _, events = d.handle(b"FLUSHALL\r\n")
        assert any("FLUSHALL" in e.command.upper() for e in events)

    def test_monitor_logged(self):
        d = self._authenticated_decoy()
        _, events = d.handle(b"MONITOR\r\n")
        assert len(events) == 1

    def test_scan_logged(self):
        d = self._authenticated_decoy()
        _, events = d.handle(b"SCAN 0\r\n")
        assert len(events) == 1
        assert events[0].event_type == DecoyEventType.COMMAND

    def test_recon_command_returns_error(self):
        d = self._authenticated_decoy()
        resp, _ = d.handle(b"KEYS *\r\n")
        assert resp.startswith(b"-")

    def test_unknown_command_returns_error(self):
        d = self._authenticated_decoy()
        resp, events = d.handle(b"UNKNOWNCMD\r\n")
        assert resp.startswith(b"-")

    def test_recon_event_includes_source_ip_detail(self):
        d = self._authenticated_decoy()
        _, events = d.handle(b"INFO server\r\n")
        assert "5.6.7.8" in events[0].detail


# ===========================================================================
# RedisDecoy — captured_events accumulation
# ===========================================================================

class TestRedisDecoyCapturedEvents:
    def test_events_accumulate(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        d.handle(b"PING\r\n")          # no new event
        d.handle(b"AUTH badpass\r\n")  # 1 auth_attempt event
        d.handle(b"QUIT\r\n")          # 1 disconnect event
        # CONNECT(1) + AUTH_ATTEMPT(1) + DISCONNECT(1)
        assert len(d.captured_events) == 3

    def test_captured_events_returns_copy(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        e1 = d.captured_events
        d.handle(b"AUTH x\r\n")
        e2 = d.captured_events
        assert len(e2) == len(e1) + 1

    def test_protocol_is_redis_on_all_events(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        d.handle(b"AUTH test\r\n")
        for event in d.captured_events:
            assert event.protocol == DecoyProtocol.REDIS


# ===========================================================================
# RedisDecoy — multiple commands in one buffer
# ===========================================================================

class TestRedisDecoyMultiCommand:
    def test_two_commands_one_buffer(self):
        d = RedisDecoy(source_ip="1.2.3.4")
        resp, events = d.handle(b"PING\r\nAUTH badpass\r\n")
        # PONG for PING + error for AUTH
        assert b"PONG" in resp
        assert b"WRONGPASS" in resp or resp.count(b"-") >= 1
        assert len(events) == 1  # only AUTH generates an event

    def test_resp_and_inline_in_sequence(self):
        # Two separate calls to simulate streaming
        d = RedisDecoy(source_ip="1.2.3.4")
        resp1, _ = d.handle(b"PING\r\n")
        resp2, events = d.handle(b"AUTH p\r\n")
        assert b"PONG" in resp1
        assert len(events) == 1
