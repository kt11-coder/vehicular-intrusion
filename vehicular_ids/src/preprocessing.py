"""Dataset loading and preprocessing for CAN bus IDS pipelines."""

from __future__ import annotations

from pathlib import Path
from typing import Union

import pandas as pd

from src.can_decoder import CANDBCDecoder
from utils.config import (
    DEFAULT_DBC_PATH,
    MAX_UPLOAD_ROWS,
    OPTIONAL_LABEL_COLUMN,
    REQUIRED_COLUMNS,
    SAMPLE_DATASET_PATH,
)


PathLike = Union[str, Path]
DEFAULT_PAYLOAD = "0000000000000000"


def normalize_message_id(message_id: object) -> str:
    """Normalize CAN message IDs to a stable hex string such as 0x100."""
    if pd.isna(message_id):
        return "0x000"

    raw_value = str(message_id).strip()
    if not raw_value:
        return "0x000"

    try:
        if raw_value.lower().startswith("0x"):
            parsed_value = int(raw_value, 16)
        else:
            parsed_value = int(raw_value)
        return f"0x{parsed_value:X}"
    except ValueError:
        return raw_value


def normalize_data_bytes(data_bytes: object) -> str:
    """Normalize payloads to uppercase 16-hex-character strings."""
    if pd.isna(data_bytes):
        return DEFAULT_PAYLOAD

    payload = str(data_bytes).strip().replace(" ", "").upper()
    if payload.lower().startswith("0x"):
        payload = payload[2:]

    if not payload:
        return DEFAULT_PAYLOAD

    if any(character not in "0123456789ABCDEF" for character in payload):
        return DEFAULT_PAYLOAD

    return payload[:16].ljust(16, "0")


def load_dataset(
    dataset_path: PathLike = SAMPLE_DATASET_PATH,
    max_rows: int = MAX_UPLOAD_ROWS,
) -> pd.DataFrame:
    """Load a CAN dataset from CSV and validate the expected schema."""
    csv_path = Path(dataset_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    frame = pd.read_csv(csv_path)
    if len(frame) > max_rows:
        raise ValueError(
            f"Dataset has {len(frame)} rows, exceeding the configured limit of {max_rows}."
        )
    missing_columns = REQUIRED_COLUMNS.difference(frame.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Dataset is missing required columns: {missing}")

    return frame


def preprocess_can_data(
    frame: pd.DataFrame,
    max_rows: int = MAX_UPLOAD_ROWS,
    dbc_path: PathLike = DEFAULT_DBC_PATH,
) -> pd.DataFrame:
    """Clean CAN rows, decode DBC signals, and return a chronological frame."""
    if len(frame) > max_rows:
        raise ValueError(
            f"Input dataframe has {len(frame)} rows, exceeding the configured limit of {max_rows}."
        )

    missing_columns = REQUIRED_COLUMNS.difference(frame.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Input dataframe is missing required columns: {missing}")

    selected_columns = ["timestamp", "message_id", "data_bytes", "speed"]
    if OPTIONAL_LABEL_COLUMN in frame.columns:
        selected_columns.append(OPTIONAL_LABEL_COLUMN)

    cleaned = frame.loc[:, selected_columns].copy()

    cleaned["timestamp"] = pd.to_datetime(cleaned["timestamp"], errors="coerce")
    cleaned = cleaned.dropna(subset=["timestamp"])

    cleaned["message_id"] = cleaned["message_id"].fillna("0x000").map(normalize_message_id)
    cleaned["data_bytes"] = cleaned["data_bytes"].map(normalize_data_bytes)

    cleaned["speed"] = pd.to_numeric(cleaned["speed"], errors="coerce")
    speed_median = cleaned["speed"].median()
    fill_value = 0.0 if pd.isna(speed_median) else float(speed_median)
    cleaned["speed"] = cleaned["speed"].fillna(fill_value)
    cleaned = cleaned.reset_index(drop=True)

    decoder = CANDBCDecoder(dbc_path)
    decoded_records = [
        decoder.decode_payload(row["message_id"], row["data_bytes"])
        for _, row in cleaned.iterrows()
    ]
    decoded_frame = pd.DataFrame(decoded_records)
    for signal_column in [
        "vehicle_speed",
        "engine_rpm",
        "throttle_pct",
        "brake_flag",
        "coolant_temp",
        "rolling_counter",
    ]:
        cleaned[signal_column] = pd.to_numeric(
            decoded_frame.get(signal_column, pd.Series(index=cleaned.index, dtype="float64")),
            errors="coerce",
        )

    cleaned["decoded_speed"] = cleaned["vehicle_speed"].fillna(cleaned["speed"])

    cleaned = (
        cleaned.drop_duplicates()
        .sort_values("timestamp", kind="stable")
        .reset_index(drop=True)
    )

    return cleaned
