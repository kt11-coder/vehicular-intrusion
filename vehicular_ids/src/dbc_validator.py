"""DBC and dataset compatibility validation utilities."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from src.can_decoder import CANDBCDecoder
from src.preprocessing import load_dataset, normalize_data_bytes, normalize_message_id
from utils.config import DEFAULT_DBC_PATH, SAMPLE_DATASET_PATH


def validate_dbc_file(dbc_path: Path | str = DEFAULT_DBC_PATH) -> Dict[str, Any]:
    """Validate that a DBC file is readable and contains usable CAN definitions."""
    decoder = CANDBCDecoder(dbc_path)
    messages = list(decoder.messages.values())

    signal_count = sum(len(message.signals) for message in messages)
    byte_aligned_signals = 0
    invalid_signals = []
    for message in messages:
        for signal in message.signals.values():
            if signal.start_bit % 8 == 0 and signal.length % 8 == 0:
                byte_aligned_signals += 1
            else:
                invalid_signals.append(
                    {
                        "message_id": message.message_id,
                        "message_name": message.name,
                        "signal": asdict(signal),
                    }
                )

    return {
        "dbc_path": str(Path(dbc_path)),
        "message_count": len(messages),
        "signal_count": signal_count,
        "byte_aligned_signals": byte_aligned_signals,
        "unsupported_signals": invalid_signals,
        "valid": len(messages) > 0 and len(invalid_signals) == 0,
    }


def validate_dbc_against_dataset(
    dataset_path: Path | str = SAMPLE_DATASET_PATH,
    dbc_path: Path | str = DEFAULT_DBC_PATH,
) -> Dict[str, Any]:
    """Check DBC coverage and decode success against a CAN dataset."""
    decoder = CANDBCDecoder(dbc_path)
    frame = load_dataset(dataset_path)
    normalized_ids = frame["message_id"].map(normalize_message_id)
    normalized_payloads = frame["data_bytes"].map(normalize_data_bytes)

    unique_dataset_ids = sorted(set(normalized_ids.tolist()))
    dbc_ids = set(decoder.messages.keys())
    known_ids = sorted(set(unique_dataset_ids).intersection(dbc_ids))
    unknown_ids = sorted(set(unique_dataset_ids).difference(dbc_ids))

    decode_attempts = 0
    decode_success = 0
    for message_id, payload in zip(normalized_ids, normalized_payloads):
        if message_id not in dbc_ids:
            continue
        decode_attempts += 1
        if decoder.decode_payload(message_id, payload):
            decode_success += 1

    return {
        "dataset_path": str(Path(dataset_path)),
        "dbc_path": str(Path(dbc_path)),
        "dataset_rows": int(len(frame)),
        "dataset_unique_ids": len(unique_dataset_ids),
        "dbc_message_count": len(dbc_ids),
        "covered_dataset_ids": known_ids,
        "missing_dataset_ids_in_dbc": unknown_ids,
        "dbc_coverage_ratio": round(
            len(known_ids) / max(len(unique_dataset_ids), 1),
            4,
        ),
        "decode_success_ratio": round(
            decode_success / max(decode_attempts, 1),
            4,
        ),
        "valid": len(known_ids) > 0 and decode_success > 0,
    }
