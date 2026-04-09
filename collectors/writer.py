"""
Event writer — outputs HoneypotEvents to stdout and an optional JSONL file.

JSONL (JSON Lines) format: one JSON object per line, enabling streaming
ingestion by SIEM tools and log aggregators.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Optional
from honeypots.common.event import HoneypotEvent


class EventWriter:
    def __init__(self, output_file: Optional[Path] = None) -> None:
        self._output_file = output_file
        self._file_handle = None
        if output_file:
            self._file_handle = output_file.open("a", buffering=1)  # line-buffered

    def write(self, event: HoneypotEvent) -> None:
        """Serialize event to JSON and write to stdout and optional file."""
        line = json.dumps(event.model_dump(mode="json")) + "\n"
        sys.stdout.write(line)
        sys.stdout.flush()
        if self._file_handle:
            self._file_handle.write(line)

    def close(self) -> None:
        if self._file_handle:
            self._file_handle.close()

    def __enter__(self) -> "EventWriter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
