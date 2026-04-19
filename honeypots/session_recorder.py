from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionEvent:
    ts: str
    type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSession:
    session_id: str
    protocol: str
    source_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    started_at: str = field(default_factory=_utc_now_iso)
    ended_at: str | None = None
    events: list[SessionEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "events": [
                {"ts": e.ts, "type": e.type, "data": e.data} for e in self.events
            ],
        }


class AttackSessionRecorder:
    """
    Thread-safe in-memory recorder for attacker session activity.

    Produces replayable JSON artifacts containing a full interaction timeline,
    including command and upload events.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, AttackSession] = {}
        self._lock = threading.Lock()

    def start_session(
        self,
        protocol: str,
        source_ip: str,
        source_port: int | None = None,
        destination_port: int | None = None,
        session_id: str | None = None,
    ) -> str:
        sid = session_id or str(uuid.uuid4())
        session = AttackSession(
            session_id=sid,
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
        )
        with self._lock:
            self._sessions[sid] = session
        self.record_event(sid, "session_started", {})
        return sid

    def record_event(self, session_id: str, event_type: str, data: dict[str, Any]) -> None:
        event = SessionEvent(ts=_utc_now_iso(), type=event_type, data=data)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session.events.append(event)

    def record_command(self, session_id: str, command: str, cwd: str | None = None) -> None:
        payload: dict[str, Any] = {"command": command}
        if cwd:
            payload["cwd"] = cwd
        self.record_event(session_id, "command", payload)

    def record_upload(
        self,
        session_id: str,
        filename: str,
        size_bytes: int | None = None,
        sha256: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"filename": filename}
        if size_bytes is not None:
            payload["size_bytes"] = size_bytes
        if sha256:
            payload["sha256"] = sha256
        self.record_event(session_id, "upload", payload)

    def end_session(self, session_id: str, reason: str | None = None) -> Path | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            session.ended_at = _utc_now_iso()
            session.events.append(
                SessionEvent(
                    ts=session.ended_at,
                    type="session_ended",
                    data={"reason": reason} if reason else {},
                )
            )
            data = session.to_dict()
            del self._sessions[session_id]

        out_path = self.output_dir / f"session-{session_id}.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return out_path
