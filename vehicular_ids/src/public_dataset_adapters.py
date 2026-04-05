"""Adapters for real-world public CAN IDS datasets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, Optional

import pandas as pd

from src.preprocessing import normalize_data_bytes, normalize_message_id


CANDUMP_PATTERN = re.compile(
    r"^\((?P<timestamp>\d+(?:\.\d+)?)\)\s+"
    r"(?P<channel>\S+)\s+"
    r"(?P<message_id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)"
)


def _normalize_hex_can_id(value: object) -> str:
    raw_value = str(value).strip()
    if not raw_value:
        return "0x000"
    if raw_value.lower().startswith("0x"):
        return normalize_message_id(raw_value)
    try:
        return f"0x{int(raw_value, 16):X}"
    except ValueError:
        return normalize_message_id(raw_value)


def _join_payload_bytes(values: Iterable[object]) -> str:
    bytes_text = "".join(
        str(value).strip().replace("0x", "").replace("0X", "").zfill(2)
        for value in values
        if pd.notna(value) and str(value).strip() != ""
    )
    return normalize_data_bytes(bytes_text)


def load_hcrl_car_hacking_dataset(dataset_path: Path | str) -> pd.DataFrame:
    """Convert HCRL Car-Hacking/OTIDS CSV logs into the internal IDS schema."""
    source_path = Path(dataset_path)
    frame = pd.read_csv(source_path)
    lower_columns = {column.lower().strip(): column for column in frame.columns}

    timestamp_col = lower_columns.get("timestamp")
    message_id_col = (
        lower_columns.get("can id")
        or lower_columns.get("id")
        or lower_columns.get("arbitration id")
    )
    flag_col = lower_columns.get("flag") or lower_columns.get("label")

    if timestamp_col is None or message_id_col is None:
        raise ValueError(
            "HCRL dataset must include timestamp and CAN ID / ID columns."
        )

    data_columns = []
    for index in range(8):
        for candidate in [f"data[{index}]", f"data{index}", f"data_{index}"]:
            if candidate in lower_columns:
                data_columns.append(lower_columns[candidate])
                break

    if not data_columns:
        payload_col = lower_columns.get("payload") or lower_columns.get("data")
        if payload_col is None:
            raise ValueError(
                "HCRL dataset must include DATA[0..7] columns or a Payload column."
            )
        payload_series = frame[payload_col].map(normalize_data_bytes)
    else:
        payload_series = frame.loc[:, data_columns].apply(
            lambda row: _join_payload_bytes(row.tolist()),
            axis=1,
        )

    label_series = pd.Series("normal", index=frame.index)
    if flag_col is not None:
        raw_labels = frame[flag_col].astype(str).str.strip().str.upper()
        label_series = raw_labels.map(
            {
                "T": "attack",
                "R": "normal",
                "1": "attack",
                "1.0": "attack",
                "0": "normal",
                "0.0": "normal",
            }
        ).fillna("normal")

    return pd.DataFrame(
        {
            "timestamp": pd.to_datetime(frame[timestamp_col], unit="s", errors="coerce"),
            "message_id": frame[message_id_col].map(_normalize_hex_can_id),
            "data_bytes": payload_series,
            "speed": 0.0,
            "ground_truth": label_series,
        }
    ).dropna(subset=["timestamp"])


def _extract_attack_windows(metadata: Dict[str, object]) -> list[tuple[float, float]]:
    """Best-effort extraction of ROAD-style attack windows from metadata JSON."""
    windows: list[tuple[float, float]] = []

    for key, value in metadata.items():
        if isinstance(value, dict):
            windows.extend(_extract_attack_windows(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    windows.extend(_extract_attack_windows(item))
                elif (
                    isinstance(item, list)
                    and len(item) >= 2
                    and all(isinstance(number, (int, float)) for number in item[:2])
                ):
                    windows.append((float(item[0]), float(item[1])))
        elif (
            "interval" in key.lower()
            and isinstance(value, str)
            and "," in value
        ):
            pieces = value.replace("[", "").replace("]", "").split(",")
            if len(pieces) >= 2:
                try:
                    windows.append((float(pieces[0]), float(pieces[1])))
                except ValueError:
                    continue

    return windows


def _infer_road_labels(
    timestamps: pd.Series,
    metadata_path: Optional[Path],
) -> pd.Series:
    labels = pd.Series("normal", index=timestamps.index)
    if metadata_path is None or not metadata_path.exists():
        return labels

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception:
        return labels

    windows = _extract_attack_windows(metadata)
    if not windows:
        return labels

    rel_seconds = (timestamps - timestamps.min()).dt.total_seconds()
    for start_time, end_time in windows:
        labels.loc[(rel_seconds >= start_time) & (rel_seconds <= end_time)] = "attack"
    return labels


def load_road_candump_log(
    log_path: Path | str,
    metadata_path: Path | str | None = None,
) -> pd.DataFrame:
    """Convert ROAD/candump raw CAN logs into the internal IDS schema."""
    source_path = Path(log_path)
    rows = []

    with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = CANDUMP_PATTERN.match(line.strip())
            if not match:
                continue
            rows.append(
                {
                    "timestamp": pd.to_datetime(
                        float(match.group("timestamp")),
                        unit="s",
                        errors="coerce",
                    ),
                    "message_id": normalize_message_id(
                        f"0x{match.group('message_id')}"
                    ),
                    "data_bytes": normalize_data_bytes(match.group("data")),
                    "speed": 0.0,
                }
            )

    frame = pd.DataFrame(rows).dropna(subset=["timestamp"])
    metadata = Path(metadata_path) if metadata_path is not None else None
    if not frame.empty:
        frame["ground_truth"] = _infer_road_labels(frame["timestamp"], metadata)
    else:
        frame["ground_truth"] = pd.Series(dtype="object")
    return frame


def convert_public_dataset(
    source_path: Path | str,
    dataset_format: str,
    output_path: Path | str,
    metadata_path: Path | str | None = None,
) -> Path:
    """Convert a supported public CAN dataset into this project's canonical CSV."""
    format_name = dataset_format.strip().lower()
    if format_name in {"hcrl", "car_hacking", "otids"}:
        frame = load_hcrl_car_hacking_dataset(source_path)
    elif format_name in {"road", "candump"}:
        frame = load_road_candump_log(source_path, metadata_path=metadata_path)
    else:
        raise ValueError(
            "Unsupported dataset_format. Use one of: hcrl, car_hacking, otids, road, candump."
        )

    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(target_path, index=False)
    return target_path
