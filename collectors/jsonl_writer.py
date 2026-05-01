from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable


class RotatingJsonlWriter:
    def __init__(
        self,
        output_file: str | None,
        max_bytes: int = 0,
        max_backups: int = 5,
        telemetry_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.output_file = output_file
        self.max_bytes = max(0, int(max_bytes or 0))
        self.max_backups = max(1, int(max_backups or 1))
        self.telemetry_callback = telemetry_callback

    def write_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        print(line)

        if not self.output_file:
            return

        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.max_bytes > 0 and output_path.exists() and output_path.stat().st_size >= self.max_bytes:
            self._rotate(output_path)

        with output_path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.write("\n")

    def _rotate(self, output_path: Path) -> None:
        # Remove oldest backup if it exists and retention is bounded.
        oldest = output_path.with_name(f"{output_path.name}.{self.max_backups}")
        if oldest.exists():
            oldest.unlink(missing_ok=True)
            self._emit_prune_telemetry(output_path, str(oldest), self.max_backups)

        # Shift existing backups up by one.
        for i in range(self.max_backups - 1, 0, -1):
            src = output_path.with_name(f"{output_path.name}.{i}")
            dst = output_path.with_name(f"{output_path.name}.{i + 1}")
            if src.exists():
                os.replace(src, dst)

        # Move current file to .1
        first = output_path.with_name(f"{output_path.name}.1")
        if output_path.exists():
            os.replace(output_path, first)

    def _emit_prune_telemetry(self, output_path: Path, pruned_file: str, max_backups: int) -> None:
        if not self.telemetry_callback:
            return
        self.telemetry_callback(
            {
                "event_type": "jsonl_rotation_pruned",
                "output_file": str(output_path),
                "pruned_file": pruned_file,
                "max_backups": max_backups,
            }
        )
