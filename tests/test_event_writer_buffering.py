import json

import pytest

from collectors.event_writer import EventWriter


@pytest.mark.asyncio
async def test_buffered_file_flush_and_shutdown_flush(tmp_path, capsys):
    out_file = tmp_path / "events.jsonl"
    writer = EventWriter(output_file=str(out_file), output_buffer_size=3, flush_interval_seconds=60.0)

    await writer.write_event({"n": 1})
    await writer.write_event({"n": 2})

    # stdout remains immediate
    stdout_lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(stdout_lines) >= 2

    # file not yet flushed because buffer size not reached
    assert out_file.read_text(encoding="utf-8") == ""

    # third write should trigger batch flush
    await writer.write_event({"n": 3})
    file_lines = [ln for ln in out_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert [json.loads(ln)["n"] for ln in file_lines] == [1, 2, 3]

    # buffered event should be flushed on shutdown
    await writer.write_event({"n": 4})
    await writer.close()

    file_lines = [ln for ln in out_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert [json.loads(ln)["n"] for ln in file_lines] == [1, 2, 3, 4]
