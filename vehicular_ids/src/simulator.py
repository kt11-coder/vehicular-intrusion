"""Synthetic CAN traffic generator with normal and attack scenarios."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from utils.config import (
    DEMO_DATASET_PATH,
    NORMAL_SPEED_RANGES,
    OPTIONAL_LABEL_COLUMN,
    REQUIRED_COLUMNS,
    SAMPLE_DATASET_PATH,
    SIMULATOR_SETTINGS,
    UNKNOWN_MESSAGE_IDS,
    WHITELISTED_MESSAGE_IDS,
)


class CANDatasetSimulator:
    """Generate realistic CAN-like traffic and deterministic attack bursts."""

    def __init__(
        self,
        start_time: str = "2026-04-04 09:00:00",
        random_seed: int = SIMULATOR_SETTINGS["seed"],
    ) -> None:
        self.start_time = pd.Timestamp(start_time)
        self.rng = np.random.default_rng(random_seed)

    @staticmethod
    def _normalize_message_id(message_id: str) -> str:
        return f"0x{int(str(message_id), 16):X}"

    def _build_payload(
        self,
        message_id: str,
        speed: float,
        sequence_counter: int,
    ) -> str:
        message_numeric = int(message_id, 16) if str(message_id).startswith("0x") else 0
        encoded_speed = int(np.clip(speed, 0, 655.35) * 100)
        rpm_value = int(self.rng.integers(700, 4200))
        throttle = int(self.rng.integers(0, 101))
        brake = int(self.rng.integers(0, 2))
        temperature = int(self.rng.integers(60, 110))

        payload_bytes = [
            (encoded_speed >> 8) & 0xFF,
            encoded_speed & 0xFF,
            (rpm_value >> 8) & 0xFF,
            rpm_value & 0xFF,
            throttle & 0xFF,
            brake & 0xFF,
            temperature & 0xFF,
            (message_numeric + sequence_counter) & 0xFF,
        ]
        return "".join(f"{byte_value:02X}" for byte_value in payload_bytes)

    def _sample_normal_speed(self, message_id: str) -> float:
        low, high = NORMAL_SPEED_RANGES[message_id]
        return round(float(self.rng.uniform(low, high)), 2)

    def _packet(
        self,
        timestamp: pd.Timestamp,
        message_id: str,
        speed: float,
        sequence_counter: int,
        data_bytes: str | None = None,
        ground_truth: str = "normal",
    ) -> Dict[str, object]:
        normalized_id = self._normalize_message_id(message_id)
        return {
            "timestamp": timestamp,
            "message_id": normalized_id,
            "data_bytes": data_bytes
            if data_bytes is not None
            else self._build_payload(normalized_id, speed, sequence_counter),
            "speed": round(float(speed), 2),
            "ground_truth": ground_truth,
        }

    def _generate_normal_traffic(self, packet_count: int) -> pd.DataFrame:
        weighted_ids = np.array(list(WHITELISTED_MESSAGE_IDS), dtype=object)
        probabilities = np.array([0.20, 0.18, 0.16, 0.16, 0.15, 0.10, 0.05])
        probabilities = probabilities / probabilities.sum()

        packets: List[Dict[str, object]] = []
        current_time = self.start_time

        for sequence_counter in range(packet_count):
            current_time += pd.to_timedelta(
                float(self.rng.uniform(0.005, 0.045)),
                unit="s",
            )
            message_id = str(self.rng.choice(weighted_ids, p=probabilities))
            speed = self._sample_normal_speed(message_id)
            packets.append(
                self._packet(
                    timestamp=current_time,
                    message_id=message_id,
                    speed=speed,
                    sequence_counter=sequence_counter,
                    ground_truth="normal",
                )
            )

        return pd.DataFrame(packets)

    def _generate_flood_attack(
        self,
        start_timestamp: pd.Timestamp,
        packet_count: int,
    ) -> pd.DataFrame:
        packets: List[Dict[str, object]] = []
        flood_id = "0x100"
        current_time = start_timestamp

        for sequence_counter in range(packet_count):
            current_time += pd.to_timedelta(0.001, unit="s")
            speed = round(float(self.rng.uniform(45, 120)), 2)
            packets.append(
                self._packet(
                    timestamp=current_time,
                    message_id=flood_id,
                    speed=speed,
                    sequence_counter=10_000 + sequence_counter,
                    ground_truth="flood_attack",
                )
            )

        return pd.DataFrame(packets)

    def _generate_replay_attack(
        self,
        start_timestamp: pd.Timestamp,
        normal_frame: pd.DataFrame,
        packet_count: int,
    ) -> pd.DataFrame:
        replay_ids = ["0x100", "0x101", "0x102", "0x200"]
        replay_template: List[Dict[str, object]] = []

        for message_id in replay_ids:
            matched_rows = normal_frame.loc[normal_frame["message_id"] == message_id]
            if matched_rows.empty:
                speed = self._sample_normal_speed(message_id)
                replay_template.append(
                    self._packet(
                        start_timestamp,
                        message_id,
                        speed,
                        sequence_counter=20_000,
                        ground_truth="replay_attack",
                    )
                )
            else:
                replay_template.append(matched_rows.iloc[0].to_dict())

        packets: List[Dict[str, object]] = []
        current_time = start_timestamp
        cycles = max(1, packet_count // len(replay_template))

        for cycle_index in range(cycles):
            for template_row in replay_template:
                current_time += pd.to_timedelta(0.001, unit="s")
                packets.append(
                    self._packet(
                        timestamp=current_time,
                        message_id=str(template_row["message_id"]),
                        speed=float(template_row["speed"]),
                        sequence_counter=30_000 + cycle_index,
                        data_bytes=str(template_row["data_bytes"]),
                        ground_truth="replay_attack",
                    )
                )

        return pd.DataFrame(packets)

    def _generate_unknown_id_attack(
        self,
        start_timestamp: pd.Timestamp,
        packet_count: int,
    ) -> pd.DataFrame:
        packets: List[Dict[str, object]] = []
        current_time = start_timestamp

        for sequence_counter in range(packet_count):
            current_time += pd.to_timedelta(
                float(self.rng.uniform(0.01, 0.04)),
                unit="s",
            )
            message_id = str(self.rng.choice(UNKNOWN_MESSAGE_IDS))
            speed = round(float(self.rng.uniform(10, 140)), 2)
            packets.append(
                self._packet(
                    timestamp=current_time,
                    message_id=message_id,
                    speed=speed,
                    sequence_counter=40_000 + sequence_counter,
                    ground_truth="unknown_id",
                )
            )

        return pd.DataFrame(packets)

    def _generate_invalid_speed_events(
        self,
        start_timestamp: pd.Timestamp,
        packet_count: int,
    ) -> pd.DataFrame:
        packets: List[Dict[str, object]] = []
        current_time = start_timestamp
        valid_ids = ["0x100", "0x101", "0x200"]

        for sequence_counter in range(packet_count):
            current_time += pd.to_timedelta(0.02, unit="s")
            message_id = valid_ids[sequence_counter % len(valid_ids)]
            speed = round(float(self.rng.uniform(320, 420)), 2)
            packets.append(
                self._packet(
                    timestamp=current_time,
                    message_id=message_id,
                    speed=speed,
                    sequence_counter=50_000 + sequence_counter,
                    ground_truth="invalid_value",
                )
            )

        return pd.DataFrame(packets)

    def generate_dataset(self) -> pd.DataFrame:
        """Generate normal CAN traffic plus flood, replay, unknown-ID, and value attacks."""
        normal_frame = self._generate_normal_traffic(
            SIMULATOR_SETTINGS["normal_packets"]
        )

        flood_frame = self._generate_flood_attack(
            start_timestamp=self.start_time + pd.Timedelta(seconds=30),
            packet_count=SIMULATOR_SETTINGS["flood_packets"],
        )
        replay_frame = self._generate_replay_attack(
            start_timestamp=self.start_time + pd.Timedelta(seconds=60),
            normal_frame=normal_frame,
            packet_count=SIMULATOR_SETTINGS["replay_packets"],
        )
        unknown_id_frame = self._generate_unknown_id_attack(
            start_timestamp=self.start_time + pd.Timedelta(seconds=90),
            packet_count=SIMULATOR_SETTINGS["unknown_id_packets"],
        )
        invalid_speed_frame = self._generate_invalid_speed_events(
            start_timestamp=self.start_time + pd.Timedelta(seconds=120),
            packet_count=SIMULATOR_SETTINGS["invalid_speed_packets"],
        )

        combined = pd.concat(
            [
                normal_frame,
                flood_frame,
                replay_frame,
                unknown_id_frame,
                invalid_speed_frame,
            ],
            ignore_index=True,
        )
        combined = combined.sort_values("timestamp", kind="stable").reset_index(drop=True)
        combined["timestamp"] = combined["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        return combined

    def save_dataset(self, dataset_path: Path | str = SAMPLE_DATASET_PATH) -> Path:
        output_path = Path(dataset_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        dataset = self.generate_dataset()
        dataset.to_csv(output_path, index=False)
        return output_path


def ensure_sample_dataset(dataset_path: Path | str = SAMPLE_DATASET_PATH) -> Path:
    """Create the sample CAN dataset if it is not already available."""
    output_path = Path(dataset_path)
    if output_path.exists():
        try:
            existing_columns = set(pd.read_csv(output_path, nrows=5).columns)
        except Exception:
            existing_columns = set()
        expected_columns = REQUIRED_COLUMNS.union({OPTIONAL_LABEL_COLUMN})
        if expected_columns.issubset(existing_columns):
            return output_path

    simulator = CANDatasetSimulator()
    return simulator.save_dataset(output_path)


def save_current_demo_dataset(
    dataset_path: Path | str = DEMO_DATASET_PATH,
    start_time: str | pd.Timestamp | None = None,
) -> Path:
    """Generate a demo dataset anchored to the current local time."""
    anchor_time = pd.Timestamp.now().floor("s") if start_time is None else pd.Timestamp(start_time)
    simulator = CANDatasetSimulator(start_time=str(anchor_time))
    return simulator.save_dataset(dataset_path)


if __name__ == "__main__":
    saved_path = ensure_sample_dataset()
    print(f"Synthetic CAN dataset saved to: {saved_path}")
