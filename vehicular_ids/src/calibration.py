"""Threshold calibration from baseline CAN traffic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

from src.feature_engineering import engineer_features
from src.hybrid_detector import HybridAnomalyDetector
from src.preprocessing import load_dataset, preprocess_can_data
from src.rule_engine import RuleEngine
from utils.config import (
    CALIBRATION_NORMAL_QUANTILE,
    CALIBRATION_REPLAY_QUANTILE,
    CALIBRATION_REPORT_PATH,
    DEFAULT_DBC_PATH,
    OPTIONAL_LABEL_COLUMN,
    SAMPLE_DATASET_PATH,
    WHITELISTED_MESSAGE_IDS,
)


def _select_baseline_rows(frame: pd.DataFrame) -> pd.DataFrame:
    if OPTIONAL_LABEL_COLUMN in frame.columns:
        normal_rows = frame.loc[
            frame[OPTIONAL_LABEL_COLUMN].fillna("normal").astype(str).str.lower() == "normal"
        ]
        if not normal_rows.empty:
            return normal_rows.copy()

    ordered = frame.sort_values("timestamp", kind="stable")
    return ordered.head(max(100, int(len(ordered) * 0.3))).copy()


def calibrate_thresholds_from_dataset(
    dataset_path: Path | str = SAMPLE_DATASET_PATH,
    dbc_path: Path | str = DEFAULT_DBC_PATH,
    output_path: Path | str = CALIBRATION_REPORT_PATH,
) -> Dict[str, Any]:
    """Estimate rule and anomaly thresholds from baseline traffic statistics."""
    raw_frame = load_dataset(dataset_path)
    processed_frame = preprocess_can_data(raw_frame, dbc_path=dbc_path)
    feature_frame = engineer_features(processed_frame)
    baseline = _select_baseline_rows(feature_frame)

    finite_time_diff = (
        pd.to_numeric(baseline["time_diff"], errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .dropna()
    )
    repeated_normal_time_diff = finite_time_diff.loc[finite_time_diff > 0]

    detector = HybridAnomalyDetector()
    detector.fit(feature_frame)
    anomaly_scores = detector.score(baseline)

    recommended = {
        "flood_threshold": max(
            20,
            int(
                np.ceil(
                    baseline["messages_per_second"].quantile(CALIBRATION_NORMAL_QUANTILE)
                    * 1.20
                )
            ),
        ),
        "replay_min_time_diff_seconds": round(
            float(
                max(
                    0.001,
                    repeated_normal_time_diff.quantile(CALIBRATION_REPLAY_QUANTILE)
                    if not repeated_normal_time_diff.empty
                    else 0.01,
                )
            ),
            6,
        ),
        "replay_repeat_threshold": max(
            3,
            int(
                np.ceil(
                    baseline["payload_changed"].eq(0).rolling(20, min_periods=1).sum().quantile(0.99)
                )
            ),
        ),
        "sequence_repeat_threshold": max(
            3,
            int(np.ceil(baseline["sequence_repeat_count"].quantile(CALIBRATION_NORMAL_QUANTILE) + 1)),
        ),
        "max_valid_speed": round(
            float(
                max(
                    120.0,
                    pd.to_numeric(baseline["decoded_speed"], errors="coerce")
                    .fillna(baseline["speed"])
                    .quantile(0.999)
                    + 20.0,
                )
            ),
            2,
        ),
        "anomaly_score_threshold": round(
            float(max(0.50, anomaly_scores.quantile(CALIBRATION_NORMAL_QUANTILE))),
            4,
        ),
        "whitelist": sorted(set(WHITELISTED_MESSAGE_IDS).union(set(baseline["message_id"].astype(str).unique()))),
    }

    report = {
        "dataset_path": str(Path(dataset_path)),
        "baseline_rows": int(len(baseline)),
        "calibration_quantile": CALIBRATION_NORMAL_QUANTILE,
        "recommended_thresholds": recommended,
        "baseline_summary": {
            "max_messages_per_second": int(baseline["messages_per_second"].max()),
            "median_time_diff": round(
                float(repeated_normal_time_diff.median()) if not repeated_normal_time_diff.empty else 0.0,
                6,
            ),
            "max_sequence_repeat_count": int(baseline["sequence_repeat_count"].max()),
            "max_decoded_speed": round(
                float(
                    pd.to_numeric(baseline["decoded_speed"], errors="coerce")
                    .fillna(baseline["speed"])
                    .max()
                ),
                2,
            ),
        },
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def calibrated_rule_engine(calibration_report: Dict[str, Any]) -> RuleEngine:
    """Build a RuleEngine instance from calibration output."""
    thresholds = calibration_report["recommended_thresholds"]
    return RuleEngine(
        whitelist=set(thresholds["whitelist"]),
        flood_threshold=int(thresholds["flood_threshold"]),
        replay_min_time_diff_seconds=float(thresholds["replay_min_time_diff_seconds"]),
        replay_repeat_threshold=int(thresholds["replay_repeat_threshold"]),
        sequence_repeat_threshold=int(thresholds["sequence_repeat_threshold"]),
        max_valid_speed=float(thresholds["max_valid_speed"]),
    )
