"""Regression tests for the vehicular IDS pipeline."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.auth import verify_credentials
from src.calibration import calibrate_thresholds_from_dataset, calibrated_rule_engine
from src.can_decoder import CANDBCDecoder
from src.dbc_validator import validate_dbc_against_dataset, validate_dbc_file
from src.evaluation import evaluate_detection_performance
from src.operational_report import generate_operational_report
from src.pipeline import run_ids_pipeline
from src.preprocessing import normalize_data_bytes, normalize_message_id, preprocess_can_data
from src.public_dataset_adapters import (
    convert_public_dataset,
    load_hcrl_car_hacking_dataset,
    load_road_candump_log,
)
from src.rule_engine import RuleEngine
from src.simulator import CANDatasetSimulator, save_current_demo_dataset
from src.storage import IDSStorage
from src.streaming import CsvReplayStreamReader
from utils.config import DEFAULT_DBC_PATH


class TestPreprocessing(unittest.TestCase):
    def test_normalization_and_missing_values(self) -> None:
        raw_frame = pd.DataFrame(
            [
                {
                    "timestamp": "2026-04-04 09:00:00.001",
                    "message_id": "256",
                    "data_bytes": "0xabc",
                    "speed": None,
                },
                {
                    "timestamp": "2026-04-04 09:00:00.002",
                    "message_id": "0x100",
                    "data_bytes": "not-hex",
                    "speed": 55.5,
                },
            ]
        )

        processed = preprocess_can_data(raw_frame)

        self.assertEqual(processed.loc[0, "message_id"], "0x100")
        self.assertEqual(processed.loc[0, "data_bytes"], "ABC0000000000000")
        self.assertEqual(processed.loc[1, "data_bytes"], "0000000000000000")
        self.assertAlmostEqual(processed.loc[0, "speed"], 55.5)

    def test_helper_normalizers(self) -> None:
        self.assertEqual(normalize_message_id("0X1ab"), "0x1AB")
        self.assertEqual(normalize_message_id("419"), "0x1A3")
        self.assertEqual(normalize_data_bytes("0x1F 2a"), "1F2A000000000000")
        self.assertEqual(normalize_data_bytes("bad-payload"), "0000000000000000")


class TestRulePipeline(unittest.TestCase):
    def test_demo_dataset_helper_can_anchor_to_current_demo_start_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_path = Path(temp_dir) / "demo_sample.csv"
            save_current_demo_dataset(
                dataset_path=dataset_path,
                start_time="2026-05-06 10:15:00",
            )

            frame = pd.read_csv(dataset_path)

            self.assertTrue(dataset_path.exists())
            self.assertTrue(frame["timestamp"].iloc[0].startswith("2026-05-06"))
            self.assertIn("ground_truth", frame.columns)

    def test_pipeline_detects_all_expected_attack_types(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_path = Path(temp_dir) / "sample_can.csv"
            simulator = CANDatasetSimulator(random_seed=42)
            simulator.save_dataset(dataset_path)

            result = run_ids_pipeline(dataset_path=dataset_path)
            alert_types = set(result.alert_frame["alert_type"].tolist())

            self.assertGreater(len(result.feature_frame), 1000)
            self.assertGreater(result.summary["total_alerts"], 0)
            self.assertTrue(
                {
                    "Flood Attack",
                    "Unknown ID",
                    "Replay Attack",
                    "Sequence Anomaly",
                    "Invalid Value",
                }.issubset(alert_types)
            )

    def test_custom_whitelist_changes_unknown_id_detection(self) -> None:
        frame = pd.DataFrame(
            [
                {
                    "timestamp": "2026-04-04 09:00:00.001",
                    "message_id": "0x100",
                    "data_bytes": "0011223344556677",
                    "speed": 10,
                },
                {
                    "timestamp": "2026-04-04 09:00:00.010",
                    "message_id": "0x777",
                    "data_bytes": "8899AABBCCDDEEFF",
                    "speed": 15,
                },
            ]
        )

        strict_engine = RuleEngine(whitelist={"0x100"})
        result = run_ids_pipeline(raw_frame=frame, rule_engine=strict_engine)
        self.assertIn("Unknown ID", set(result.alert_frame["alert_type"].tolist()))

        permissive_engine = RuleEngine(whitelist={"0x100", "0x777"})
        result = run_ids_pipeline(raw_frame=frame, rule_engine=permissive_engine)
        self.assertNotIn("Unknown ID", set(result.alert_frame["alert_type"].tolist()))

    def test_metrics_are_available_for_labeled_data(self) -> None:
        simulator = CANDatasetSimulator(random_seed=42)
        dataset = simulator.generate_dataset()
        result = run_ids_pipeline(raw_frame=dataset)

        metrics = evaluate_detection_performance(result.feature_frame, result.alert_frame)

        self.assertTrue(metrics["available"])
        self.assertGreaterEqual(metrics["recall"], 0.5)
        self.assertGreaterEqual(metrics["precision"], 0.1)


class TestDBCAndStorage(unittest.TestCase):
    def test_can_decoder_extracts_signals(self) -> None:
        decoder = CANDBCDecoder(DEFAULT_DBC_PATH)
        decoded = decoder.decode_payload("0x100", "2EF403E846004002")

        self.assertIn("vehicle_speed", decoded)
        self.assertIn("engine_rpm", decoded)
        self.assertGreaterEqual(decoded["vehicle_speed"], 0)

    def test_storage_persists_pipeline_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "ids.sqlite3"
            storage = IDSStorage(db_path)

            simulator = CANDatasetSimulator(random_seed=42)
            frame = simulator.generate_dataset().head(200)
            result = run_ids_pipeline(
                raw_frame=frame,
                storage=storage,
                persist_results=True,
            )

            stored_alerts = storage.fetch_alerts(limit=100)
            stored_packets = storage.fetch_packets(limit=300)

            self.assertGreater(len(result.feature_frame), 0)
            self.assertGreater(len(stored_packets), 0)
            self.assertGreaterEqual(len(stored_alerts), 0)

    def test_dbc_validation_and_calibration_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_path = Path(temp_dir) / "sample.csv"
            calibration_path = Path(temp_dir) / "calibration.json"
            report_path = Path(temp_dir) / "ops_report.md"
            CANDatasetSimulator(random_seed=42).save_dataset(dataset_path)

            dbc_report = validate_dbc_file(DEFAULT_DBC_PATH)
            coverage_report = validate_dbc_against_dataset(dataset_path, DEFAULT_DBC_PATH)
            calibration_report = calibrate_thresholds_from_dataset(
                dataset_path=dataset_path,
                output_path=calibration_path,
            )
            engine = calibrated_rule_engine(calibration_report)
            ops_report = generate_operational_report(
                dataset_path=dataset_path,
                dbc_path=DEFAULT_DBC_PATH,
                output_path=report_path,
            )

            self.assertTrue(dbc_report["valid"])
            self.assertTrue(coverage_report["valid"])
            self.assertTrue(calibration_path.exists())
            self.assertGreaterEqual(engine.flood_threshold, 20)
            self.assertTrue(report_path.exists())
            self.assertIn("output_path", ops_report)


class TestAuthAndStreaming(unittest.TestCase):
    def test_verify_credentials_supports_configured_secrets(self) -> None:
        secrets = {
            "VEHICULAR_IDS_USER": "analyst",
            "VEHICULAR_IDS_PASSWORD": "strong-pass",
        }
        self.assertTrue(verify_credentials("analyst", "strong-pass", secrets))
        self.assertFalse(verify_credentials("analyst", "wrong-pass", secrets))

    def test_csv_replay_stream_batches_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset_path = Path(temp_dir) / "sample.csv"
            CANDatasetSimulator(random_seed=42).save_dataset(dataset_path)

            reader = CsvReplayStreamReader(dataset_path=dataset_path, batch_size=25)
            batch_one = reader.next_batch()
            batch_two = reader.next_batch()

            self.assertEqual(len(batch_one), 25)
            self.assertEqual(len(batch_two), 25)
            self.assertNotEqual(
                batch_one.iloc[0]["timestamp"],
                batch_two.iloc[0]["timestamp"],
            )


class TestPublicDatasetAdapters(unittest.TestCase):
    def test_hcrl_adapter_converts_flagged_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = Path(temp_dir) / "hcrl.csv"
            output_path = Path(temp_dir) / "canonical.csv"
            pd.DataFrame(
                [
                    {
                        "Timestamp": 1478198376.389427,
                        "CAN ID": "0316",
                        "DLC": 8,
                        "DATA[0]": "05",
                        "DATA[1]": "21",
                        "DATA[2]": "68",
                        "DATA[3]": "09",
                        "DATA[4]": "21",
                        "DATA[5]": "21",
                        "DATA[6]": "00",
                        "DATA[7]": "6f",
                        "Flag": "R",
                    },
                    {
                        "Timestamp": 1478198376.400000,
                        "CAN ID": "0316",
                        "DLC": 8,
                        "DATA[0]": "08",
                        "DATA[1]": "21",
                        "DATA[2]": "68",
                        "DATA[3]": "09",
                        "DATA[4]": "21",
                        "DATA[5]": "21",
                        "DATA[6]": "00",
                        "DATA[7]": "6f",
                        "Flag": "T",
                    },
                ]
            ).to_csv(source_path, index=False)

            frame = load_hcrl_car_hacking_dataset(source_path)
            converted_path = convert_public_dataset(
                source_path,
                dataset_format="hcrl",
                output_path=output_path,
            )

            self.assertTrue(converted_path.exists())
            self.assertEqual(frame.loc[0, "message_id"], "0x316")
            self.assertEqual(frame.loc[0, "data_bytes"], "052168092121006F")
            self.assertEqual(frame.loc[0, "ground_truth"], "normal")
            self.assertEqual(frame.loc[1, "ground_truth"], "attack")

    def test_road_adapter_parses_candump_and_metadata_window(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "road.log"
            metadata_path = Path(temp_dir) / "meta.json"
            output_path = Path(temp_dir) / "road_canonical.csv"

            log_path.write_text(
                "\n".join(
                    [
                        "(1700000000.100000) can0 316#052168092121006F",
                        "(1700000001.100000) can0 316#082168092121006F",
                    ]
                ),
                encoding="utf-8",
            )
            metadata_path.write_text(
                '{"attack_intervals": [[0.5, 2.0]]}',
                encoding="utf-8",
            )

            frame = load_road_candump_log(log_path, metadata_path=metadata_path)
            converted_path = convert_public_dataset(
                log_path,
                dataset_format="road",
                output_path=output_path,
                metadata_path=metadata_path,
            )

            self.assertTrue(converted_path.exists())
            self.assertEqual(frame.loc[0, "message_id"], "0x316")
            self.assertEqual(frame.loc[0, "ground_truth"], "normal")
            self.assertEqual(frame.loc[1, "ground_truth"], "attack")


if __name__ == "__main__":
    unittest.main()
