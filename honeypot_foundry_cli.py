#!/usr/bin/env python3
"""honeypot_foundry_cli.py

Main CLI entrypoint for honeypot-foundry.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


@dataclass
class JsonlOutputWriter:
    stdout: TextIO
    output_file: str | None = None
    output_file_fallback_stdout_on_error: bool = False
    _fh: TextIO | None = None
    _file_disabled: bool = False
    _warned_once: bool = False

    def __post_init__(self) -> None:
        if self.output_file:
            self._fh = Path(self.output_file).open("a", encoding="utf-8")

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        self.stdout.write(line + "\n")
        self.stdout.flush()

        if not self._fh or self._file_disabled:
            return

        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except Exception as exc:  # pragma: no cover - explicit behavior tested via monkeypatch
            if not self.output_file_fallback_stdout_on_error:
                raise
            self._file_disabled = True
            if not self._warned_once:
                self._warned_once = True
                warning = {
                    "event_type": "metric.output_file_write_error_fallback_stdout",
                    "level": "warning",
                    "message": "output file write failed; disabling file sink and continuing with stdout",
                    "error": str(exc),
                    "output_file": self.output_file,
                }
                self.stdout.write(json.dumps(warning, separators=(",", ":"), ensure_ascii=False) + "\n")
                self.stdout.flush()



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument("--output-file", default=None)
    parser.add_argument(
        "--output-file-fallback-stdout-on-error",
        action="store_true",
        help=(
            "If set, keep service running and continue stdout output when JSONL file writes fail. "
            "Default is fail-fast."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    writer = JsonlOutputWriter(
        stdout=sys.stdout,
        output_file=args.output_file,
        output_file_fallback_stdout_on_error=args.output_file_fallback_stdout_on_error,
    )

    writer.emit({"event_type": "startup", "ok": True})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
