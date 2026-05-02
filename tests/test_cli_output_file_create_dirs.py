from __future__ import annotations

import pytest

from cli.output import open_output_file


def test_open_output_file_fails_when_parent_missing_by_default(tmp_path):
    missing_parent_file = tmp_path / "missing" / "nested" / "events.jsonl"

    with pytest.raises(FileNotFoundError):
        open_output_file(str(missing_parent_file), create_dirs=False)


def test_open_output_file_creates_parent_dirs_when_flag_enabled(tmp_path):
    output_file = tmp_path / "missing" / "nested" / "events.jsonl"

    handle = open_output_file(str(output_file), create_dirs=True)
    assert handle is not None
    handle.write('{"ok":true}\n')
    handle.close()

    assert output_file.exists()
    assert output_file.parent.exists()
