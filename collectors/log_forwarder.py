import json
import socket
import time
import logging
from logging.handlers import SysLogHandler
from urllib import request


class LogForwarder:
    """
    Centralized honeypot event forwarder.

    Supports:
    - Syslog (UDP/TCP)
    - HTTP POST
    - Beats-style TCP JSON streaming
    """

    def __init__(
        self,
        syslog_host=None,
        syslog_port=514,
        syslog_protocol="udp",
        http_endpoint=None,
        beats_host=None,
        beats_port=None,
        timeout=5,
    ):
        self.http_endpoint = http_endpoint
        self.timeout = timeout

        self.syslog_logger = None
        if syslog_host:
            socktype = socket.SOCK_DGRAM if syslog_protocol.lower() == "udp" else socket.SOCK_STREAM
            handler = SysLogHandler(address=(syslog_host, syslog_port), socktype=socktype)
            logger = logging.getLogger("honeypot_forwarder_syslog")
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            self.syslog_logger = logger

        self.beats_socket = None
        if beats_host and beats_port:
            self.beats_socket = socket.create_connection((beats_host, beats_port), timeout=self.timeout)

    def _send_syslog(self, event):
        if not self.syslog_logger:
            return
        try:
            self.syslog_logger.info(json.dumps(event))
        except Exception:
            pass

    def _send_http(self, event):
        if not self.http_endpoint:
            return
        try:
            data = json.dumps(event).encode()
            req = request.Request(
                self.http_endpoint,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            request.urlopen(req, timeout=self.timeout).read()
        except Exception:
            pass

    def _send_beats(self, event):
        if not self.beats_socket:
            return
        try:
            line = json.dumps(event) + "\n"
            self.beats_socket.sendall(line.encode())
        except Exception:
            pass

    def forward_event(self, event: dict):
        """Forward a single structured honeypot event."""
        self._send_syslog(event)
        self._send_http(event)
        self._send_beats(event)

    def forward_jsonl_file(self, path, follow=True, poll_interval=0.5):
        """
        Stream events from a JSONL file and forward them.

        Designed for honeypot output files like events.jsonl.
        """
        with open(path, "r") as f:
            if follow:
                f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    if not follow:
                        break
                    time.sleep(poll_interval)
                    continue

                try:
                    event = json.loads(line.strip())
                    self.forward_event(event)
                except Exception:
                    continue
