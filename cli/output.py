from __future__ import annotations

from pathlib import Path
from typing import TextIO


def open_output_file(path: str | None, *, line_buffered: bool = False, create_dirs: bool = False) -> TextIO | None:
    """Open an output file sink for JSONL writing.

    Default behavior is fail-fast if parent directories do not exist.
    When create_dirs=True, missing parent directories are created first.
    """
    if not path:
        return None

    output_path = Path(path)
    parent = output_path.parent
    if create_dirs and parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)

    buffering = 1 if line_buffered else -1
    return output_path.open("a", encoding="utf-8", buffering=buffering)
