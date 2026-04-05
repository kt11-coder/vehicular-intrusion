"""Feature extraction for deterministic CAN intrusion detection rules."""

from __future__ import annotations

import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view

from utils.config import (
    ROLLING_FREQUENCY_WINDOW,
    SEQUENCE_REPEAT_TIME_BUCKET,
    SEQUENCE_WINDOW_SIZE,
)


def _payload_entropy(payload: str) -> float:
    text = str(payload or "")
    if not text:
        return 0.0

    values = pd.Series(list(text)).value_counts(normalize=True).to_numpy(dtype=float)
    return float(-(values * np.log2(values)).sum())


def _add_message_rate_features(
    frame: pd.DataFrame,
    rolling_window: str,
) -> pd.DataFrame:
    features = frame.copy()
    features["second_bucket"] = features["timestamp"].dt.floor("s")
    features["messages_per_second"] = (
        features.groupby("second_bucket")["message_id"].transform("size").astype(int)
    )

    # Per-message timing delta is used by replay detection.
    features["time_diff"] = (
        features.groupby("message_id")["timestamp"]
        .diff()
        .dt.total_seconds()
        .fillna(np.inf)
    )
    features["payload_changed"] = (
        features.groupby("message_id")["data_bytes"]
        .transform(lambda series: series.ne(series.shift(1)).astype(int))
        .fillna(1)
        .astype(int)
    )
    features["payload_entropy"] = features["data_bytes"].map(_payload_entropy)

    features["rolling_frequency_per_id"] = 0.0
    features["rolling_speed_std_per_id"] = 0.0
    for _, group in features.groupby("message_id", sort=False):
        time_indexed = group.set_index("timestamp")
        rolling_count = time_indexed["message_id"].rolling(rolling_window).count().to_numpy(
            dtype=float
        )
        features.loc[group.index, "rolling_frequency_per_id"] = rolling_count
        speed_std = (
            time_indexed["decoded_speed"]
            .rolling(rolling_window)
            .std()
            .fillna(0.0)
            .to_numpy(dtype=float)
            if "decoded_speed" in time_indexed.columns
            else np.zeros(len(group), dtype=float)
        )
        features.loc[group.index, "rolling_speed_std_per_id"] = speed_std

    if "decoded_speed" in features.columns:
        features["speed_signal_delta"] = (
            features["decoded_speed"] - features["speed"]
        ).abs()
    else:
        features["speed_signal_delta"] = 0.0

    return features


def _add_sequence_features(
    frame: pd.DataFrame,
    sequence_window_size: int,
    sequence_repeat_time_bucket: str,
) -> pd.DataFrame:
    features = frame.copy()
    features["sequence_signature"] = ""
    features["sequence_repeat_count"] = 0
    features["sequence_time_bucket"] = features["timestamp"].dt.floor(
        sequence_repeat_time_bucket
    )

    if len(features) < sequence_window_size:
        return features

    message_ids = features["message_id"].astype(str).to_numpy()
    sequence_windows = sliding_window_view(message_ids, sequence_window_size)
    sequence_signatures = np.array(
        ["|".join(window.tolist()) for window in sequence_windows],
        dtype=object,
    )

    features.loc[
        sequence_window_size - 1 :,
        "sequence_signature",
    ] = sequence_signatures

    valid_sequence_mask = features["sequence_signature"] != ""
    if valid_sequence_mask.any():
        features.loc[valid_sequence_mask, "sequence_repeat_count"] = (
            features.loc[valid_sequence_mask]
            .groupby(["sequence_signature", "sequence_time_bucket"])[
                "sequence_signature"
            ]
            .transform("size")
            .astype(int)
        )

    return features


def engineer_features(
    frame: pd.DataFrame,
    rolling_window: str = ROLLING_FREQUENCY_WINDOW,
    sequence_window_size: int = SEQUENCE_WINDOW_SIZE,
    sequence_repeat_time_bucket: str = SEQUENCE_REPEAT_TIME_BUCKET,
) -> pd.DataFrame:
    """Compute rate, timing, rolling-frequency, and sequence-repeat features."""
    if frame.empty:
        empty = frame.copy()
        empty["second_bucket"] = pd.Series(dtype="datetime64[ns]")
        empty["messages_per_second"] = pd.Series(dtype="int64")
        empty["time_diff"] = pd.Series(dtype="float64")
        empty["payload_changed"] = pd.Series(dtype="int64")
        empty["payload_entropy"] = pd.Series(dtype="float64")
        empty["rolling_frequency_per_id"] = pd.Series(dtype="float64")
        empty["rolling_speed_std_per_id"] = pd.Series(dtype="float64")
        empty["speed_signal_delta"] = pd.Series(dtype="float64")
        empty["sequence_signature"] = pd.Series(dtype="object")
        empty["sequence_repeat_count"] = pd.Series(dtype="int64")
        empty["sequence_time_bucket"] = pd.Series(dtype="datetime64[ns]")
        return empty

    ordered_frame = frame.sort_values("timestamp", kind="stable").reset_index(drop=True)
    features = _add_message_rate_features(ordered_frame, rolling_window)
    features = _add_sequence_features(
        features,
        sequence_window_size=sequence_window_size,
        sequence_repeat_time_bucket=sequence_repeat_time_bucket,
    )
    return features
