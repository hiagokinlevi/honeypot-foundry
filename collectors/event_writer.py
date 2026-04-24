import asyncio
import contextlib
import json
import sys
from typing import Any, Dict, List, Optional, TextIO


class EventWriter:
    """Writes structured events to stdout and/or JSONL file.

    Stdout behavior remains immediate (line-by-line) for observability.
    File output supports optional in-memory buffering to reduce disk I/O.
    """

    def __init__(
        self,
        output_file: Optional[str] = None,
        output_buffer_size: int = 1,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        self._output_file_path = output_file
        self._output_file: Optional[TextIO] = None
        self._output_buffer_size = max(1, int(output_buffer_size))
        self._flush_interval_seconds = flush_interval_seconds
        self._file_buffer: List[str] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._stopping = False

        if self._output_file_path:
            self._output_file = open(self._output_file_path, "a", encoding="utf-8")
            if self._output_buffer_size > 1:
                self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def write_event(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)

        # Keep stdout behavior unchanged: immediate flush per line
        print(line, file=sys.stdout, flush=True)

        if not self._output_file:
            return

        if self._output_buffer_size <= 1:
            self._output_file.write(line + "\n")
            self._output_file.flush()
            return

        self._file_buffer.append(line)
        if len(self._file_buffer) >= self._output_buffer_size:
            self._flush_file_buffer()

    def _flush_file_buffer(self) -> None:
        if not self._output_file or not self._file_buffer:
            return
        self._output_file.write("\n".join(self._file_buffer) + "\n")
        self._output_file.flush()
        self._file_buffer.clear()

    async def _periodic_flush_loop(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self._flush_interval_seconds)
                self._flush_file_buffer()
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        self._stopping = True
        if self._flush_task:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
        self._flush_file_buffer()
        if self._output_file:
            self._output_file.close()
            self._output_file = None
