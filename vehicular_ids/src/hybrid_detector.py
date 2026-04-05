"""Hybrid statistical anomaly detector layered on top of rule-based IDS."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from utils.config import ANOMALY_SCORE_THRESHOLD, OPTIONAL_LABEL_COLUMN


@dataclass
class HybridAnomalyDetector:
    """Compute robust anomaly scores and emit incident-level ML alerts."""

    score_threshold: float = ANOMALY_SCORE_THRESHOLD
    feature_columns: List[str] = field(
        default_factory=lambda: [
            "messages_per_second",
            "time_diff",
            "rolling_frequency_per_id",
            "payload_entropy",
            "rolling_speed_std_per_id",
            "speed_signal_delta",
            "decoded_speed",
            "engine_rpm",
            "throttle_pct",
            "coolant_temp",
        ]
    )
    center_: Dict[str, float] = field(default_factory=dict)
    scale_: Dict[str, float] = field(default_factory=dict)

    def fit(self, frame: pd.DataFrame) -> "HybridAnomalyDetector":
        if frame.empty:
            self.center_.clear()
            self.scale_.clear()
            return self

        reference_frame = frame
        if OPTIONAL_LABEL_COLUMN in frame.columns:
            normal_rows = frame.loc[
                frame[OPTIONAL_LABEL_COLUMN].fillna("normal").astype(str).str.lower()
                == "normal"
            ]
            if not normal_rows.empty:
                reference_frame = normal_rows
        else:
            ordered = frame.sort_values("timestamp", kind="stable") if "timestamp" in frame.columns else frame
            warmup_count = max(50, int(len(ordered) * 0.3))
            reference_frame = ordered.head(warmup_count)

        self.center_.clear()
        self.scale_.clear()
        for column in self.feature_columns:
            source_series = reference_frame.get(
                column,
                pd.Series(index=reference_frame.index, dtype="float64"),
            )
            series = pd.to_numeric(source_series, errors="coerce")
            series = series.replace([np.inf, -np.inf], np.nan).dropna()
            if series.empty:
                self.center_[column] = 0.0
                self.scale_[column] = 1.0
                continue

            median_value = float(series.median())
            mad = float(np.median(np.abs(series.to_numpy(dtype=float) - median_value)))
            self.center_[column] = median_value
            self.scale_[column] = max(mad * 1.4826, 1e-6)

        return self

    def score(self, frame: pd.DataFrame) -> pd.Series:
        if frame.empty:
            return pd.Series(dtype="float64")

        if not self.center_:
            self.fit(frame)

        z_scores = []
        for column in self.feature_columns:
            source_series = frame.get(
                column,
                pd.Series(index=frame.index, dtype="float64"),
            )
            values = (
                pd.to_numeric(source_series, errors="coerce")
                .replace([np.inf, -np.inf], np.nan)
                .fillna(self.center_.get(column, 0.0))
                .astype(float)
            )
            center = self.center_.get(column, 0.0)
            scale = self.scale_.get(column, 1.0)
            z_scores.append(((values - center).abs() / scale).clip(0, 25))

        z_matrix = np.vstack([score.to_numpy(dtype=float) for score in z_scores]).T
        blended = 0.65 * z_matrix.max(axis=1) + 0.35 * z_matrix.mean(axis=1)
        return pd.Series(1.0 - np.exp(-0.35 * blended), index=frame.index, dtype="float64")

    @staticmethod
    def _build_alert(row: pd.Series, packet_count: int, max_score: float) -> Dict[str, Any]:
        severity = "High" if max_score >= 0.90 else "Medium"
        return {
            "timestamp": row["timestamp"],
            "alert_type": "Hybrid ML Anomaly",
            "severity": severity,
            "message_id": row["message_id"],
            "description": (
                "Statistical anomaly score exceeded the learned baseline profile."
            ),
            "packet_count": int(packet_count),
            "window_start": row["second_bucket"],
            "window_end": row["timestamp"],
            "sample_payload": row["data_bytes"],
            "anomaly_score": round(float(max_score), 4),
        }

    def detect(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        if frame.empty:
            return []

        scored_frame = frame.copy()
        scored_frame["anomaly_score"] = self.score(scored_frame)
        anomaly_rows = scored_frame.loc[
            scored_frame["anomaly_score"] >= self.score_threshold
        ]
        if anomaly_rows.empty:
            return []

        grouped = (
            anomaly_rows.groupby(["second_bucket", "message_id"], sort=False)
            .agg(
                timestamp=("timestamp", "min"),
                packet_count=("message_id", "size"),
                anomaly_score=("anomaly_score", "max"),
                data_bytes=("data_bytes", "first"),
            )
            .reset_index()
        )

        return [
            self._build_alert(row, int(row["packet_count"]), float(row["anomaly_score"]))
            for _, row in grouped.iterrows()
        ]
