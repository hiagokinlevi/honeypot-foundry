import os

import pytest

from honeypot_foundry_cli import JsonlWriter, _build_parser, _parse_output_file_permissions


def test_parse_output_file_permissions_valid():
    assert _parse_output_file_permissions("600") == 0o600
    assert _parse_output_file_permissions("0640") == 0o640


def test_parse_output_file_permissions_invalid():
    with pytest.raises(Exception):
        _parse_output_file_permissions("999")
    with pytest.raises(Exception):
        _parse_output_file_permissions("64")


def test_cli_flag_available_for_run_commands():
    parser = _build_parser()
    args = parser.parse_args(["run-http", "--port", "8080", "--output-file-permissions", "640"])
    assert args.output_file_permissions == 0o640


def test_writer_emits_warning_when_chmod_fails(tmp_path, monkeypatch, capsys):
    out = tmp_path / "events.jsonl"

    def boom(path, mode):
        raise PermissionError("nope")

    monkeypatch.setattr(os, "chmod", boom)
    w = JsonlWriter(output_file=str(out), output_file_permissions=0o600)
    w.write({"event_type": "x"})
    err = capsys.readouterr().err
    assert "output_file_permissions_warning" in err
    assert "requested_mode" in err
