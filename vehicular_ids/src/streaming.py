"""Live CAN ingestion adapters and CSV replay utilities."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pandas as pd

from src.logging_setup import setup_logging
from src.preprocessing import normalize_data_bytes, normalize_message_id
from utils.config import SAMPLE_DATASET_PATH


LOGGER = setup_logging()


@dataclass
class CsvReplayStreamReader:
    """Replay CAN CSV rows in batches to simulate a live stream."""

    dataset_path: Path | str = SAMPLE_DATASET_PATH
    batch_size: int = 80
    replay_delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        self.dataset_path = Path(self.dataset_path)
        self._frame = pd.read_csv(self.dataset_path) if self.dataset_path.exists() else pd.DataFrame()
        self._cursor = 0

    def reset(self) -> None:
        self._cursor = 0

    def next_batch(self) -> pd.DataFrame:
        if self._frame.empty:
            return pd.DataFrame(
                columns=["timestamp", "message_id", "data_bytes", "speed", "ground_truth"]
            )

        start = self._cursor
        end = min(start + self.batch_size, len(self._frame))
        if start >= len(self._frame):
            self._cursor = 0
            start = 0
            end = min(self.batch_size, len(self._frame))

        batch = self._frame.iloc[start:end].copy()
        self._cursor = end

        if self.replay_delay_seconds > 0:
            time.sleep(self.replay_delay_seconds)

        return batch


class PythonCANStreamReader:
    """Read live CAN frames from python-can and expose them as dataframes."""

    def __init__(
        self,
        channel: str = "vcan0",
        bustype: str = "socketcan",
        bitrate: int = 500000,
        default_speed: float = 0.0,
    ) -> None:
        self.channel = channel
        self.bustype = bustype
        self.bitrate = bitrate
        self.default_speed = default_speed
        self._bus = None

        try:
            import can  # type: ignore
        except ImportError:
            self._can_module = None
            LOGGER.warning(
                "python-can is not installed; live hardware ingestion is unavailable."
            )
        else:
            self._can_module = can

    @property
    def is_available(self) -> bool:
        return self._can_module is not None

    def connect(self) -> None:
        if not self.is_available:
            raise RuntimeError(
                "python-can is not installed. Install python-can to use live bus ingestion."
            )

        if self._bus is None:
            self._bus = self._can_module.interface.Bus(
                channel=self.channel,
                bustype=self.bustype,
                bitrate=self.bitrate,
            )
            LOGGER.info(
                "Connected to CAN bus channel=%s bustype=%s bitrate=%s",
                self.channel,
                self.bustype,
                self.bitrate,
            )

    def close(self) -> None:
        if self._bus is not None:
            self._bus.shutdown()
            self._bus = None
            LOGGER.info("Closed CAN bus connection")

    def read_batch(self, max_messages: int = 200, timeout_seconds: float = 0.05) -> pd.DataFrame:
        if not self.is_available:
            raise RuntimeError(
                "python-can is not installed. Install python-can to use live bus ingestion."
            )

        self.connect()
        records = []

        for _ in range(max_messages):
            message = self._bus.recv(timeout=timeout_seconds)
            if message is None:
                break

            records.append(
                {
                    "timestamp": pd.to_datetime(message.timestamp, unit="s"),
                    "message_id": normalize_message_id(hex(int(message.arbitration_id))),
                    "data_bytes": normalize_data_bytes(message.data.hex().upper()),
                    "speed": self.default_speed,
                    "ground_truth": "live",
                }
            )

        return pd.DataFrame(records)
