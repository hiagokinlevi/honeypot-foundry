from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class EventWriter:
    output_file: str | None = None
    output_file_mode: str = "append"
    instance_id: str | None = None

    def __post_init__(self) -> None:
        if self.output_file_mode not in {"append", "overwrite"}:
            raise ValueError("output_file_mode must be 'append' or 'overwrite'")
        self._fh = None
        if self.output_file:
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if self.output_file_mode == "append" else "w"
            self._fh = open(self.output_file, mode, encoding="utf-8")

    def emit(self, event: dict[str, Any]) -> None:
        if self.instance_id and "instance_id" not in event:
            event = {**event, "instance_id": self.instance_id}
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        print(line)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
