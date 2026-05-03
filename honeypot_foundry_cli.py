import argparse
import json
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests


LOG = logging.getLogger("honeypot-foundry")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_telemetry(event: Dict[str, Any]) -> None:
    try:
        sys.stdout.write(json.dumps(event) + "\n")
        sys.stdout.flush()
    except Exception:
        LOG.exception("failed to emit telemetry")


def _forward_splunk(event: Dict[str, Any], endpoint: str, token: str) -> None:
    headers = {"Authorization": f"Splunk {token}"}
    payload = {"event": event}
    r = requests.post(endpoint, json=payload, headers=headers, timeout=5)
    r.raise_for_status()


def _forward_elastic(event: Dict[str, Any], endpoint: str) -> None:
    ndjson = json.dumps({"index": {}}) + "\n" + json.dumps(event) + "\n"
    r = requests.post(endpoint, data=ndjson, headers={"Content-Type": "application/x-ndjson"}, timeout=5)
    r.raise_for_status()


def _forward_cef(event: Dict[str, Any], host: str, port: int) -> None:
    msg = f"CEF:0|honeypot-foundry|honeypot|1.0|100|event|5|msg={json.dumps(event, separators=(',', ':'))}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg.encode("utf-8", errors="replace"), (host, port))
    finally:
        sock.close()


def _forward_with_retries(
    event: Dict[str, Any],
    mode: str,
    retries: int,
    splunk_endpoint: Optional[str] = None,
    splunk_token: Optional[str] = None,
    elastic_endpoint: Optional[str] = None,
    cef_host: Optional[str] = None,
    cef_port: Optional[int] = None,
) -> bool:
    attempts = retries + 1
    last_error = None

    for attempt in range(1, attempts + 1):
        try:
            if mode == "splunk":
                _forward_splunk(event, splunk_endpoint or "", splunk_token or "")
            elif mode == "elastic":
                _forward_elastic(event, elastic_endpoint or "")
            elif mode == "cef":
                _forward_cef(event, cef_host or "127.0.0.1", int(cef_port or 514))
            else:
                raise ValueError(f"unknown forwarder mode: {mode}")

            _emit_telemetry(
                {
                    "event_type": "siem_forward_status",
                    "timestamp": _utc_now(),
                    "siem_forward_target": mode,
                    "siem_forward_attempts": attempt,
                    "siem_forward_retries_configured": retries,
                    "siem_forward_final_status": "delivered",
                    "event_id": event.get("event_id"),
                }
            )
            return True
        except Exception as exc:
            last_error = str(exc)
            if attempt < attempts:
                time.sleep(0.2)

    _emit_telemetry(
        {
            "event_type": "siem_forward_status",
            "timestamp": _utc_now(),
            "siem_forward_target": mode,
            "siem_forward_attempts": attempts,
            "siem_forward_retries_configured": retries,
            "siem_forward_final_status": "dropped",
            "siem_forward_error": last_error,
            "event_id": event.get("event_id"),
        }
    )
    return False


def _bounded_retries(value: str) -> int:
    ivalue = int(value)
    if ivalue < 0 or ivalue > 10:
        raise argparse.ArgumentTypeError("--siem-forward-retries must be between 0 and 10")
    return ivalue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument("--siem-forward-retries", type=_bounded_retries, default=3, help="Retry failed SIEM forward attempts up to N times before dropping (0-10, default: 3)")
    parser.add_argument("--siem-mode", choices=["splunk", "elastic", "cef"], default=os.getenv("SIEM_MODE", "splunk"))
    parser.add_argument("--splunk-endpoint", default=os.getenv("SPLUNK_HEC_ENDPOINT"))
    parser.add_argument("--splunk-token", default=os.getenv("SPLUNK_HEC_TOKEN"))
    parser.add_argument("--elastic-endpoint", default=os.getenv("ELASTIC_BULK_ENDPOINT"))
    parser.add_argument("--cef-host", default=os.getenv("CEF_HOST", "127.0.0.1"))
    parser.add_argument("--cef-port", type=int, default=int(os.getenv("CEF_PORT", "514")))
    return parser


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = build_parser().parse_args(argv)

    event = {
        "event_id": "manual-test-event",
        "timestamp": _utc_now(),
        "event_type": "test",
        "message": "forward test",
    }

    _forward_with_retries(
        event=event,
        mode=args.siem_mode,
        retries=args.siem_forward_retries,
        splunk_endpoint=args.splunk_endpoint,
        splunk_token=args.splunk_token,
        elastic_endpoint=args.elastic_endpoint,
        cef_host=args.cef_host,
        cef_port=args.cef_port,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
