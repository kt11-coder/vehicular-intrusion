"""Class-based rule engine for real-time CAN intrusion alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set

import pandas as pd

from utils.config import (
    FLOOD_MESSAGES_PER_SECOND_THRESHOLD,
    MAX_VALID_SPEED,
    MIN_VALID_SPEED,
    REPLAY_MIN_TIME_DIFF_SECONDS,
    REPLAY_REPEAT_THRESHOLD,
    SEQUENCE_REPEAT_THRESHOLD,
    WHITELISTED_MESSAGE_IDS,
)


@dataclass
class RuleEngine:
    """Evaluate deterministic IDS rules on engineered CAN features."""

    whitelist: Set[str] = field(default_factory=lambda: set(WHITELISTED_MESSAGE_IDS))
    flood_threshold: int = FLOOD_MESSAGES_PER_SECOND_THRESHOLD
    replay_min_time_diff_seconds: float = REPLAY_MIN_TIME_DIFF_SECONDS
    replay_repeat_threshold: int = REPLAY_REPEAT_THRESHOLD
    sequence_repeat_threshold: int = SEQUENCE_REPEAT_THRESHOLD
    max_valid_speed: float = MAX_VALID_SPEED
    min_valid_speed: float = MIN_VALID_SPEED

    REQUIRED_FEATURE_COLUMNS = {
        "timestamp",
        "message_id",
        "data_bytes",
        "speed",
        "second_bucket",
        "messages_per_second",
        "time_diff",
        "sequence_signature",
        "sequence_repeat_count",
        "sequence_time_bucket",
    }

    @staticmethod
    def _build_alert(
        row: pd.Series,
        alert_type: str,
        severity: str,
        description: str,
        extra_details: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        alert = {
            "timestamp": row["timestamp"],
            "alert_type": alert_type,
            "severity": severity,
            "message_id": row["message_id"],
            "description": description,
        }
        if extra_details:
            alert.update(extra_details)
        return alert

    @classmethod
    def _validate_input_frame(cls, frame: pd.DataFrame) -> None:
        missing_columns = cls.REQUIRED_FEATURE_COLUMNS.difference(frame.columns)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(
                "Feature dataframe is missing required columns for rule evaluation: "
                f"{missing}"
            )

    def detect_flood_attack(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        flood_rows = frame.loc[
            frame["messages_per_second"] > self.flood_threshold,
            ["timestamp", "message_id", "second_bucket", "messages_per_second"],
        ]
        if flood_rows.empty:
            return []

        grouped = (
            flood_rows.groupby(["second_bucket", "message_id"], sort=False)
            .agg(
                timestamp=("timestamp", "min"),
                window_end=("timestamp", "max"),
                packet_count=("message_id", "size"),
                messages_per_second=("messages_per_second", "max"),
            )
            .reset_index()
        )

        alerts: List[Dict[str, Any]] = []
        for _, row in grouped.iterrows():
            alerts.append(
                self._build_alert(
                    row,
                    alert_type="Flood Attack",
                    severity="High",
                    description=(
                        "Packet rate exceeded the configured per-second threshold."
                    ),
                    extra_details={
                        "window_start": row["second_bucket"],
                        "window_end": row["window_end"],
                        "packet_count": int(row["packet_count"]),
                        "messages_per_second": int(row["messages_per_second"]),
                        "threshold": int(self.flood_threshold),
                    },
                )
            )
        return alerts

    def detect_unknown_id(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        unknown_rows = frame.loc[~frame["message_id"].isin(self.whitelist)]
        if unknown_rows.empty:
            return []

        grouped = (
            unknown_rows.groupby(["second_bucket", "message_id"], sort=False)
            .agg(
                timestamp=("timestamp", "min"),
                window_end=("timestamp", "max"),
                packet_count=("message_id", "size"),
                sample_payload=("data_bytes", "first"),
            )
            .reset_index()
        )

        return [
            self._build_alert(
                row,
                alert_type="Unknown ID",
                severity="High",
                description="CAN message ID is not present in the whitelist.",
                extra_details={
                    "window_start": row["timestamp"],
                    "window_end": row["window_end"],
                    "packet_count": int(row["packet_count"]),
                    "sample_payload": row["sample_payload"],
                },
            )
            for _, row in grouped.iterrows()
        ]

    def detect_replay_attack(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []

        for _, group in frame.groupby("message_id", sort=False):
            repeated_payload = group["data_bytes"].eq(group["data_bytes"].shift(1))
            short_interval = group["time_diff"] < self.replay_min_time_diff_seconds
            suspicious = repeated_payload & short_interval
            suspicious_rows = group.loc[suspicious].copy()
            if suspicious_rows.empty:
                continue

            streak_group = (~suspicious).cumsum()
            for _, replay_group in suspicious_rows.groupby(streak_group.loc[suspicious_rows.index]):
                if len(replay_group) < self.replay_repeat_threshold:
                    continue

                row = replay_group.iloc[0]
                alerts.append(
                    self._build_alert(
                        row,
                        alert_type="Replay Attack",
                        severity="High",
                        description=(
                            "Repeated payload replayed for the same CAN ID with "
                            "abnormally short inter-arrival times."
                        ),
                        extra_details={
                            "window_start": replay_group["timestamp"].min(),
                            "window_end": replay_group["timestamp"].max(),
                            "packet_count": int(len(replay_group) + 1),
                            "sample_payload": row["data_bytes"],
                            "min_observed_time_diff": float(
                                replay_group["time_diff"].min()
                            ),
                            "min_time_diff_threshold": float(
                                self.replay_min_time_diff_seconds
                            ),
                        },
                    )
                )

        return alerts

    def detect_sequence_anomaly(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        anomaly_rows = frame.loc[
            (frame["sequence_signature"] != "")
            & (frame["sequence_repeat_count"] > self.sequence_repeat_threshold)
        ]

        if anomaly_rows.empty:
            return []

        grouped = (
            anomaly_rows.groupby(
                ["sequence_time_bucket", "sequence_signature", "message_id"],
                sort=False,
            )
            .agg(
                timestamp=("timestamp", "min"),
                sequence_repeat_count=("sequence_repeat_count", "max"),
            )
            .reset_index()
        )

        alerts: List[Dict[str, Any]] = []
        for _, row in grouped.iterrows():
            alerts.append(
                self._build_alert(
                    row,
                    alert_type="Sequence Anomaly",
                    severity="Medium",
                    description=(
                        "Repeated identical CAN ID sequence detected inside a short "
                        "time window."
                    ),
                    extra_details={
                        "sequence_signature": row["sequence_signature"],
                        "sequence_repeat_count": int(row["sequence_repeat_count"]),
                        "packet_count": int(row["sequence_repeat_count"]),
                        "window_start": row["sequence_time_bucket"],
                        "window_end": row["timestamp"],
                        "repeat_threshold": int(self.sequence_repeat_threshold),
                    },
                )
            )
        return alerts

    def detect_invalid_value(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        decoded_speed = pd.to_numeric(
            frame.get("decoded_speed", frame["speed"]),
            errors="coerce",
        ).fillna(frame["speed"])
        invalid_rows = frame.loc[
            (frame["speed"] > self.max_valid_speed)
            | (decoded_speed > self.max_valid_speed)
            | (frame["speed"] < self.min_valid_speed)
            | (decoded_speed < self.min_valid_speed)
        ].copy()
        if invalid_rows.empty:
            return []

        invalid_rows["decoded_speed"] = decoded_speed.loc[invalid_rows.index]

        grouped = (
            invalid_rows.groupby(["second_bucket", "message_id"], sort=False)
            .agg(
                timestamp=("timestamp", "min"),
                window_end=("timestamp", "max"),
                packet_count=("message_id", "size"),
                max_speed=("speed", "max"),
                sample_payload=("data_bytes", "first"),
                max_decoded_speed=("decoded_speed", "max"),
            )
            .reset_index()
        )

        return [
            self._build_alert(
                row,
                alert_type="Invalid Value",
                severity="Medium",
                description="Speed exceeds the configured physical validity limit.",
                extra_details={
                    "window_start": row["timestamp"],
                    "window_end": row["window_end"],
                    "packet_count": int(row["packet_count"]),
                    "max_observed_speed": float(row["max_speed"]),
                    "max_decoded_speed": float(row["max_decoded_speed"]),
                    "max_valid_speed": float(self.max_valid_speed),
                    "min_valid_speed": float(self.min_valid_speed),
                    "sample_payload": row["sample_payload"],
                },
            )
            for _, row in grouped.iterrows()
        ]

    def evaluate(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        """Run all IDS rules and return alerts in chronological order."""
        self._validate_input_frame(frame)

        all_alerts: List[Dict[str, Any]] = []
        rule_methods: Iterable = (
            self.detect_flood_attack,
            self.detect_unknown_id,
            self.detect_replay_attack,
            self.detect_sequence_anomaly,
            self.detect_invalid_value,
        )

        for method in rule_methods:
            all_alerts.extend(method(frame))

        all_alerts.sort(key=lambda alert: alert["timestamp"])
        return all_alerts
