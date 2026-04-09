"""
SSH observation server.

Implements an asyncssh server that accepts connection attempts but NEVER
grants shell access. Authentication always fails by design — the server
exists solely to log attacker behavior (IPs, usernames, attempted credentials).

Security invariant: validate_password() and validate_public_key() always
return False. No session_requested() handler is provided, so even if
authentication somehow passed, no shell would be available.
"""
from __future__ import annotations
import asyncio
from collections.abc import Callable
from typing import Optional
import asyncssh
from honeypots.common.event import HoneypotEvent, ServiceType


class _ObservationSSHServer(asyncssh.SSHServer):
    """SSHServer subclass that logs every authentication attempt and denies all access."""

    def __init__(self, event_callback: Callable[[HoneypotEvent], None]) -> None:
        self._event_callback = event_callback
        self._client_ip: str = ""
        self._client_port: int = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername", ("0.0.0.0", 0))
        self._client_ip, self._client_port = peer[0], peer[1]

    def validate_password(self, username: str, password: str) -> bool:
        """
        Record the attempt and unconditionally deny access.

        The password is passed to HoneypotEvent which masks it before storage.
        This method must ALWAYS return False — granting access would compromise
        the observation-only invariant of this server.
        """
        event = HoneypotEvent(
            service=ServiceType.SSH,
            source_ip=self._client_ip,
            source_port=self._client_port,
            username=username,
            credential_observed=password,
        )
        self._event_callback(event)
        return False  # Access never granted

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Record public key authentication attempt and deny access."""
        event = HoneypotEvent(
            service=ServiceType.SSH,
            source_ip=self._client_ip,
            source_port=self._client_port,
            username=username,
            metadata={"key_type": key.get_algorithm()},
        )
        self._event_callback(event)
        return False  # Access never granted


async def start_ssh_observation_server(
    host: str,
    port: int,
    host_key_path: str,
    event_callback: Callable[[HoneypotEvent], None],
) -> asyncssh.SSHAcceptor:
    """
    Start the SSH observation server.

    Args:
        host:           Bind address.
        port:           TCP port to listen on.
        host_key_path:  Path to the server host key file.
        event_callback: Callable invoked for every connection attempt.

    Returns:
        The running asyncssh acceptor (awaitable for lifetime management).
    """
    return await asyncssh.create_server(
        lambda: _ObservationSSHServer(event_callback),
        host=host,
        port=port,
        server_host_keys=[host_key_path],
        # Disable all authentication methods except password and public key
        # so we capture the most common attack vectors
        known_client_keys=None,
        authorized_client_keys=None,
    )
