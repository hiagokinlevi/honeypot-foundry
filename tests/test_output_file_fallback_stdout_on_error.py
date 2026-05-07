from __future__ import annotations

import io

from honeypot_foundry_cli import JsonlOutputWriter


class FailingFile:
    def write(self, _data: str) -> int:
        raise OSError("disk full")

    def flush(self) -> None:
        return None


def test_output_file_fallback_stdout_on_error_continues_stdout() -> None:
    stdout = io.StringIO()
    writer = JsonlOutputWriter(
        stdout=stdout,
        output_file=None,
        output_file_fallback_stdout_on_error=True,
    )

    writer._fh = FailingFile()

    writer.emit({"event_type": "first"})
    writer.emit({"event_type": "second"})

    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]

    assert any('"event_type":"first"' in line for line in lines)
    assert any('"event_type":"second"' in line for line in lines)
    assert sum("metric.output_file_write_error_fallback_stdout" in line for line in lines) == 1
