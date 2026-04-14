import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from collectors.log_forwarder import LogForwarder


class TestHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        TestHandler.received.append(json.loads(body.decode()))
        self.send_response(200)
        self.end_headers()


def run_server(server):
    server.serve_forever()


def test_http_forwarding():
    server = HTTPServer(("127.0.0.1", 0), TestHandler)
    thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    thread.start()

    port = server.server_port
    endpoint = f"http://127.0.0.1:{port}/event"

    forwarder = LogForwarder(http_endpoint=endpoint)

    event = {"type": "test", "source_ip": "1.2.3.4"}
    forwarder.forward_event(event)

    server.shutdown()

    assert TestHandler.received
    assert TestHandler.received[0]["type"] == "test"
