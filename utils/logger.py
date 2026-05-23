"""Project-wide structured logger."""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FMT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_initialized = False


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    global _initialized
    if _initialized:
        return

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(_FMT)

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    if not _initialized:
        setup_logging(
            level=os.environ.get("VULNPILOT_LOG_LEVEL", "INFO"),
            log_file=os.environ.get("VULNPILOT_LOG_FILE"),
        )
    return logging.getLogger(name)
