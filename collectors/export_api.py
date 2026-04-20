from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query


def _parse_ts(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        # Accept common ISO-8601 with optional trailing Z
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {value}") from exc


def _event_ts(event: dict[str, Any]) -> datetime | None:
    ts = event.get("timestamp")
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                events.append(obj)
    return events


def create_export_api(event_file: str = "events.jsonl") -> FastAPI:
    app = FastAPI(title="Honeypot Attack Data Export API", version="1.0.0")
    event_path = Path(event_file)

    @app.get("/export/events")
    def export_events(
        service: str | None = Query(default=None),
        source_ip: str | None = Query(default=None),
        start_time: str | None = Query(default=None),
        end_time: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=5000),
    ) -> dict[str, Any]:
        start_dt = _parse_ts(start_time)
        end_dt = _parse_ts(end_time)
        events = _load_events(event_path)

        filtered: list[dict[str, Any]] = []
        for event in events:
            if service and event.get("service") != service:
                continue
            if source_ip and event.get("source_ip") != source_ip:
                continue

            evt_dt = _event_ts(event)
            if start_dt and evt_dt and evt_dt < start_dt:
                continue
            if end_dt and evt_dt and evt_dt > end_dt:
                continue

            filtered.append(event)
            if len(filtered) >= limit:
                break

        return {"count": len(filtered), "events": filtered}

    @app.get("/export/stats")
    def export_stats(
        start_time: str | None = Query(default=None),
        end_time: str | None = Query(default=None),
    ) -> dict[str, Any]:
        start_dt = _parse_ts(start_time)
        end_dt = _parse_ts(end_time)
        events = _load_events(event_path)

        total = 0
        by_service: Counter[str] = Counter()
        by_source_ip: Counter[str] = Counter()

        for event in events:
            evt_dt = _event_ts(event)
            if start_dt and evt_dt and evt_dt < start_dt:
                continue
            if end_dt and evt_dt and evt_dt > end_dt:
                continue

            total += 1
            svc = event.get("service")
            if isinstance(svc, str) and svc:
                by_service[svc] += 1
            ip = event.get("source_ip")
            if isinstance(ip, str) and ip:
                by_source_ip[ip] += 1

        top_sources = [
            {"source_ip": ip, "count": count}
            for ip, count in by_source_ip.most_common(10)
        ]

        return {
            "total_events": total,
            "events_by_service": dict(by_service),
            "top_source_ips": top_sources,
        }

    @app.get("/export/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_export_api()
