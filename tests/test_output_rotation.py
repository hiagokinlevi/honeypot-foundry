from logging import FileHandler
from logging.handlers import RotatingFileHandler

from honeypot_foundry_cli import _configure_event_logger


def test_configure_event_logger_without_rotation(tmp_path):
    output = tmp_path / "events.jsonl"
    logger = _configure_event_logger(str(output))

    file_handlers = [h for h in logger.handlers if isinstance(h, FileHandler)]
    assert len(file_handlers) == 1
    assert not isinstance(file_handlers[0], RotatingFileHandler)


def test_configure_event_logger_with_rotation(tmp_path):
    output = tmp_path / "events.jsonl"
    logger = _configure_event_logger(str(output), output_max_bytes=1024, output_backups=3)

    rotating_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(rotating_handlers) == 1
    assert rotating_handlers[0].maxBytes == 1024
    assert rotating_handlers[0].backupCount == 3
