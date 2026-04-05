"""SQLite persistence for CAN packets and IDS alerts."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import pandas as pd

from src.logging_setup import setup_logging
from utils.config import DEFAULT_DB_PATH


LOGGER = setup_logging()


class IDSStorage:
    """Persist packet and alert records in a local SQLite database."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    data_bytes TEXT NOT NULL,
                    speed REAL,
                    decoded_speed REAL,
                    engine_rpm REAL,
                    throttle_pct REAL,
                    brake_flag REAL,
                    coolant_temp REAL,
                    rolling_counter REAL,
                    ground_truth TEXT,
                    messages_per_second REAL,
                    time_diff REAL,
                    rolling_frequency_per_id REAL,
                    rolling_speed_std_per_id REAL,
                    payload_entropy REAL,
                    payload_changed INTEGER,
                    speed_signal_delta REAL,
                    sequence_signature TEXT,
                    sequence_repeat_count INTEGER,
                    UNIQUE(timestamp, message_id, data_bytes, speed, ground_truth)
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    incident_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    severity_score INTEGER,
                    message_id TEXT NOT NULL,
                    description TEXT,
                    packet_count INTEGER,
                    window_start TEXT,
                    window_end TEXT,
                    sample_payload TEXT,
                    anomaly_score REAL
                );
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp
                ON packets(timestamp);
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp);
                """
            )

    @staticmethod
    def _prepare_datetime_columns(frame: pd.DataFrame) -> pd.DataFrame:
        converted = frame.copy()
        for column in ["timestamp", "window_start", "window_end", "second_bucket", "sequence_time_bucket"]:
            if column in converted.columns:
                converted[column] = pd.to_datetime(
                    converted[column],
                    errors="coerce",
                ).astype(str)
        return converted

    def save_packets(self, frame: pd.DataFrame) -> int:
        if frame.empty:
            return 0

        packet_columns = [
            "timestamp",
            "message_id",
            "data_bytes",
            "speed",
            "decoded_speed",
            "engine_rpm",
            "throttle_pct",
            "brake_flag",
            "coolant_temp",
            "rolling_counter",
            "ground_truth",
            "messages_per_second",
            "time_diff",
            "rolling_frequency_per_id",
            "rolling_speed_std_per_id",
            "payload_entropy",
            "payload_changed",
            "speed_signal_delta",
            "sequence_signature",
            "sequence_repeat_count",
        ]
        packet_frame = frame.copy()
        for column in packet_columns:
            if column not in packet_frame.columns:
                packet_frame[column] = pd.NA
        packet_frame = self._prepare_datetime_columns(packet_frame.loc[:, packet_columns])
        packet_frame = packet_frame.astype(object).where(pd.notna(packet_frame), None)

        with self._connect() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO packets (
                    timestamp,
                    message_id,
                    data_bytes,
                    speed,
                    decoded_speed,
                    engine_rpm,
                    throttle_pct,
                    brake_flag,
                    coolant_temp,
                    rolling_counter,
                    ground_truth,
                    messages_per_second,
                    time_diff,
                    rolling_frequency_per_id,
                    rolling_speed_std_per_id,
                    payload_entropy,
                    payload_changed,
                    speed_signal_delta,
                    sequence_signature,
                    sequence_repeat_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                packet_frame.itertuples(index=False, name=None),
            )

        LOGGER.info("Persisted %s packet rows to %s", len(packet_frame), self.db_path)
        return int(len(packet_frame))

    def save_alerts(self, alert_frame: pd.DataFrame) -> int:
        if alert_frame.empty:
            return 0

        alert_columns = [
            "incident_id",
            "timestamp",
            "alert_type",
            "severity",
            "severity_score",
            "message_id",
            "description",
            "packet_count",
            "window_start",
            "window_end",
            "sample_payload",
            "anomaly_score",
        ]
        prepared_alerts = alert_frame.copy()
        for column in alert_columns:
            if column not in prepared_alerts.columns:
                prepared_alerts[column] = pd.NA
        prepared_alerts = self._prepare_datetime_columns(prepared_alerts.loc[:, alert_columns])
        prepared_alerts = prepared_alerts.astype(object).where(pd.notna(prepared_alerts), None)

        with self._connect() as connection:
            for row in prepared_alerts.itertuples(index=False):
                connection.execute(
                    """
                    INSERT OR REPLACE INTO alerts (
                        incident_id,
                        timestamp,
                        alert_type,
                        severity,
                        severity_score,
                        message_id,
                        description,
                        packet_count,
                        window_start,
                        window_end,
                        sample_payload,
                        anomaly_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    tuple(row),
                )

        LOGGER.info("Persisted %s alerts to %s", len(prepared_alerts), self.db_path)
        return int(len(prepared_alerts))

    def fetch_alerts(self, limit: Optional[int] = 500) -> pd.DataFrame:
        query = "SELECT * FROM alerts ORDER BY timestamp DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        with self._connect() as connection:
            return pd.read_sql_query(query, connection)

    def fetch_packets(self, limit: Optional[int] = 1000) -> pd.DataFrame:
        query = "SELECT * FROM packets ORDER BY timestamp DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        with self._connect() as connection:
            return pd.read_sql_query(query, connection)

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM alerts;")
            connection.execute("DELETE FROM packets;")
        LOGGER.info("Cleared IDS storage at %s", self.db_path)
