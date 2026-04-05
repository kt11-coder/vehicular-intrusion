"""Benchmark and metric utilities for IDS detection quality."""

from __future__ import annotations

from typing import Dict

import pandas as pd

from utils.config import OPTIONAL_LABEL_COLUMN


ALERT_TO_LABEL = {
    "Flood Attack": "flood_attack",
    "Unknown ID": "unknown_id",
    "Replay Attack": "replay_attack",
    "Sequence Anomaly": "replay_attack",
    "Invalid Value": "invalid_value",
}


def _mark_detected_packets(
    feature_frame: pd.DataFrame,
    alert_frame: pd.DataFrame,
) -> pd.Series:
    detected = pd.Series(False, index=feature_frame.index)
    if feature_frame.empty or alert_frame.empty:
        return detected

    packet_times = pd.to_datetime(feature_frame["timestamp"], errors="coerce")
    for alert in alert_frame.itertuples(index=False):
        message_id = str(getattr(alert, "message_id"))
        window_start = pd.to_datetime(
            getattr(alert, "window_start", getattr(alert, "timestamp", None)),
            errors="coerce",
        )
        window_end = pd.to_datetime(
            getattr(alert, "window_end", getattr(alert, "timestamp", None)),
            errors="coerce",
        )
        if pd.isna(window_start):
            window_start = pd.to_datetime(getattr(alert, "timestamp"), errors="coerce")
        if pd.isna(window_end):
            window_end = pd.to_datetime(getattr(alert, "timestamp"), errors="coerce")

        mask = (
            feature_frame["message_id"].astype(str).eq(message_id)
            & (packet_times >= window_start)
            & (packet_times <= window_end)
        )
        detected |= mask.fillna(False)

    return detected


def evaluate_detection_performance(
    feature_frame: pd.DataFrame,
    alert_frame: pd.DataFrame,
) -> Dict[str, object]:
    """Compute packet-level binary metrics and per-attack recall."""
    if OPTIONAL_LABEL_COLUMN not in feature_frame.columns:
        return {
            "available": False,
            "reason": f"Missing ground-truth column: {OPTIONAL_LABEL_COLUMN}",
        }

    labels = (
        feature_frame[OPTIONAL_LABEL_COLUMN]
        .fillna("normal")
        .astype(str)
        .str.lower()
    )
    actual_attack = labels.ne("normal")
    predicted_attack = _mark_detected_packets(feature_frame, alert_frame)

    true_positive = int((actual_attack & predicted_attack).sum())
    false_positive = int((~actual_attack & predicted_attack).sum())
    true_negative = int((~actual_attack & ~predicted_attack).sum())
    false_negative = int((actual_attack & ~predicted_attack).sum())

    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0
    accuracy = (
        (true_positive + true_negative)
        / max(true_positive + false_positive + true_negative + false_negative, 1)
    )
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    false_positive_rate = false_positive / (false_positive + true_negative) if (false_positive + true_negative) else 0.0

    per_attack_recall: Dict[str, float] = {}
    for attack_label in sorted(label for label in labels.unique() if label != "normal"):
        attack_mask = labels.eq(attack_label)
        total = int(attack_mask.sum())
        detected = int((attack_mask & predicted_attack).sum())
        per_attack_recall[attack_label] = detected / total if total else 0.0

    return {
        "available": True,
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1_score), 4),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "per_attack_recall": per_attack_recall,
    }
