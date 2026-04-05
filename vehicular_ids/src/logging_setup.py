"""Logging configuration shared across CLI, dashboard, and storage layers."""

from __future__ import annotations

import logging
from pathlib import Path

from utils.config import DEFAULT_LOG_PATH


def setup_logging(
    log_path: Path | str = DEFAULT_LOG_PATH,
    logger_name: str = "vehicular_ids",
) -> logging.Logger:
    """Create an idempotent file + console logger."""
    logger = logging.getLogger(logger_name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.propagate = False
    return logger
