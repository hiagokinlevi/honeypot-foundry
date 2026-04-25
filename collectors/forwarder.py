from __future__ import annotations

import json
import logging
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class SIEMRetryItem:
    event: Dict[str, Any]
    attempts: int = 0
    last_error: Optional[str] = None


class SIEMForwarder:
    def __init__(
        self,
        *,
        mode: Optional[str] = None,
        splunk_url: Optional[str] = None,
        splunk_token: Optional[str] = None,
        elastic_url: Optional[str] = None,
        cef_host: Optional[str] = None,
        cef_port: int = 514,
        timeout: float = 3.0,
        retry_interval: float = 5.0,
        max_queue: int = 1000,
        telemetry_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.mode = (mode or "").lower() or None
        self.splunk_url = splunk_url
        self.splunk_token = splunk_token
        self.elastic_url = elastic_url
        self.cef_host = cef_host
        self.cef_port = cef_port
        self.timeout = timeout
        self.retry_interval = max(0.5, retry_interval)
        self.max_queue = max(1, int(max_queue))
        self.telemetry_emitter = telemetry_emitter

        self._retry_q: Deque[SIEMRetryItem] = deque(maxlen=self.max_queue)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._retry_loop, name="siem-retry", daemon=True)
        self._worker.start()

    def close(self) -> None:
        self._stop.set()
        if self._worker.is_alive():
            self._worker.join(timeout=1.0)

    def submit(self, event: Dict[str, Any]) -> None:
        if not self.mode:
            return

        ok, err = self._deliver(event)
        if ok:
            return

        self._enqueue_retry(event, err)

    def _enqueue_retry(self, event: Dict[str, Any], error: str) -> None:
        dropped = None
        with self._lock:
            if len(self._retry_q) >= self.max_queue:
                dropped = self._retry_q.popleft()
            self._retry_q.append(SIEMRetryItem(event=event, attempts=1, last_error=error))

        if dropped is not None:
            self._emit_telemetry(
                "siem_delivery_dropped",
                {
                    "reason": "queue_full",
                    "queue_max": self.max_queue,
                    "dropped_event_id": dropped.event.get("event_id"),
                    "last_error": dropped.last_error,
                },
            )

        self._emit_telemetry(
            "siem_delivery_retry",
            {
                "reason": "initial_failure",
                "queue_depth": self.queue_depth,
                "event_id": event.get("event_id"),
                "error": error,
                "attempt": 1,
            },
        )

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return len(self._retry_q)

    def _retry_loop(self) -> None:
        while not self._stop.wait(self.retry_interval):
            item = None
            with self._lock:
                if self._retry_q:
                    item = self._retry_q.popleft()
            if item is None:
                continue

            ok, err = self._deliver(item.event)
            if ok:
                continue

            item.attempts += 1
            item.last_error = err

            dropped = False
            with self._lock:
                if len(self._retry_q) >= self.max_queue:
                    self._retry_q.popleft()
                    dropped = True
                self._retry_q.append(item)

            self._emit_telemetry(
                "siem_delivery_retry",
                {
                    "reason": "retry_failure",
                    "queue_depth": self.queue_depth,
                    "event_id": item.event.get("event_id"),
                    "error": err,
                    "attempt": item.attempts,
                },
            )
            if dropped:
                self._emit_telemetry(
                    "siem_delivery_dropped",
                    {
                        "reason": "queue_full",
                        "queue_max": self.max_queue,
                        "event_id": item.event.get("event_id"),
                        "last_error": err,
                    },
                )

    def _emit_telemetry(self, event_type: str, fields: Dict[str, Any]) -> None:
        if not self.telemetry_emitter:
            return
        payload = {"event_type": event_type, "ts": int(time.time()), **fields}
        try:
            self.telemetry_emitter(payload)
        except Exception:
            logger.exception("failed to emit SIEM telemetry event")

    def _deliver(self, event: Dict[str, Any]) -> tuple[bool, str]:
        try:
            if self.mode == "splunk":
                headers = {"Authorization": f"Splunk {self.splunk_token}", "Content-Type": "application/json"}
                data = {"event": event}
                r = requests.post(self.splunk_url, headers=headers, json=data, timeout=self.timeout)
                if r.status_code >= 400:
                    return False, f"splunk_http_{r.status_code}"
                return True, ""

            if self.mode == "elastic":
                ndjson = json.dumps({"index": {}}) + "\n" + json.dumps(event) + "\n"
                headers = {"Content-Type": "application/x-ndjson"}
                r = requests.post(self.elastic_url, data=ndjson.encode("utf-8"), headers=headers, timeout=self.timeout)
                if r.status_code >= 400:
                    return False, f"elastic_http_{r.status_code}"
                return True, ""

            if self.mode == "cef":
                msg = self._to_cef(event)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(msg.encode("utf-8", errors="replace"), (self.cef_host, self.cef_port))
                finally:
                    sock.close()
                return True, ""

            return False, "unknown_mode"
        except Exception as exc:
            return False, str(exc)

    def _to_cef(self, event: Dict[str, Any]) -> str:
        sig = event.get("event_type", "honeypot_event")
        src = event.get("src_ip", "")
        ext = f"src={src} msg={json.dumps(event, separators=(',', ':'))}"
        return f"CEF:0|honeypot-foundry|honeypot|1.0|{sig}|{sig}|5|{ext}"
