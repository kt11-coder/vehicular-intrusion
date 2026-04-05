"""Command-line entry point for the rule-based vehicular CAN IDS pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.calibration import calibrate_thresholds_from_dataset, calibrated_rule_engine
from src.evaluation import evaluate_detection_performance
from src.operational_report import generate_operational_report
from src.pipeline import PipelineResult, run_ids_pipeline
from src.storage import IDSStorage
from utils.config import (
    CALIBRATION_REPORT_PATH,
    DEFAULT_ALERT_EXPORT_PATH,
    DEFAULT_DB_PATH,
    DEFAULT_DBC_PATH,
    OPERATIONAL_REPORT_PATH,
    SAMPLE_DATASET_PATH,
)


def print_pipeline_summary(result: PipelineResult, alerts_output_path: Path) -> None:
    alert_frame = result.alert_frame
    summary = result.summary

    print("Vehicular CAN IDS Summary")
    print("=" * 60)
    print(f"Dataset path: {result.source}")
    print(f"Total packets processed: {len(result.feature_frame)}")
    print(f"Total alert events generated: {summary['total_alerts']}")
    print(f"Total impacted packets: {summary['total_impacted_packets']}")

    print("\nAlerts by type:")
    if summary["alerts_by_type"]:
        for alert_type, count in summary["alerts_by_type"].items():
            print(f"  - {alert_type}: {count}")
    else:
        print("  - None")

    print("\nAlerts by severity:")
    if summary["alerts_by_severity"]:
        for severity, count in summary["alerts_by_severity"].items():
            print(f"  - {severity}: {count}")
    else:
        print("  - None")

    metrics = evaluate_detection_performance(result.feature_frame, alert_frame)
    if metrics.get("available"):
        print("\nBenchmark metrics:")
        print(f"  - Accuracy: {metrics['accuracy']:.4f}")
        print(f"  - Precision: {metrics['precision']:.4f}")
        print(f"  - Recall: {metrics['recall']:.4f}")
        print(f"  - F1 score: {metrics['f1_score']:.4f}")
        print(f"  - False positive rate: {metrics['false_positive_rate']:.4f}")

    print("\nRecent alerts:")
    if alert_frame.empty:
        print("  - No alerts detected")
    else:
        display_columns = [
            "incident_id",
            "timestamp",
            "alert_type",
            "severity",
            "severity_score",
            "message_id",
            "description",
            "packet_count",
        ]
        print(alert_frame.loc[:, display_columns].tail(20).to_string(index=False))

    alerts_output_path.parent.mkdir(parents=True, exist_ok=True)
    result.alert_system.export_csv(str(alerts_output_path))
    print(f"\nAlert report exported to: {alerts_output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run rule-based intrusion detection on CAN bus traffic logs."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=SAMPLE_DATASET_PATH,
        help="Path to the CAN CSV dataset. If missing, a synthetic sample is generated.",
    )
    parser.add_argument(
        "--alerts-output",
        type=Path,
        default=DEFAULT_ALERT_EXPORT_PATH,
        help="Path where the generated alert report CSV will be written.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="SQLite database path used to persist packets and alerts.",
    )
    parser.add_argument(
        "--dbc-path",
        type=Path,
        default=DEFAULT_DBC_PATH,
        help="Path to the DBC file used for decoding CAN payloads.",
    )
    parser.add_argument(
        "--calibrate-thresholds",
        action="store_true",
        help="Estimate rule thresholds from baseline traffic and save a calibration report.",
    )
    parser.add_argument(
        "--calibration-output",
        type=Path,
        default=CALIBRATION_REPORT_PATH,
        help="Where to write the threshold calibration JSON report.",
    )
    parser.add_argument(
        "--operational-report",
        action="store_true",
        help="Generate a markdown deployment-readiness report after the IDS run.",
    )
    parser.add_argument(
        "--operational-report-output",
        type=Path,
        default=OPERATIONAL_REPORT_PATH,
        help="Where to write the operational validation markdown report.",
    )
    parser.add_argument(
        "--disable-hybrid",
        action="store_true",
        help="Disable the statistical anomaly detector and run rule-only mode.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rule_engine = None
    if args.calibrate_thresholds:
        calibration_report = calibrate_thresholds_from_dataset(
            dataset_path=args.dataset,
            dbc_path=args.dbc_path,
            output_path=args.calibration_output,
        )
        rule_engine = calibrated_rule_engine(calibration_report)
        print("Calibrated thresholds saved to:", args.calibration_output)
        print(json.dumps(calibration_report["recommended_thresholds"], indent=2))

    storage = IDSStorage(args.db_path)
    result = run_ids_pipeline(
        dataset_path=args.dataset,
        dbc_path=args.dbc_path,
        rule_engine=rule_engine,
        storage=storage,
        enable_hybrid_detection=not args.disable_hybrid,
        persist_results=True,
    )
    print_pipeline_summary(result, args.alerts_output)
    print(f"SQLite persistence path: {args.db_path}")

    if args.operational_report:
        report = generate_operational_report(
            dataset_path=args.dataset,
            dbc_path=args.dbc_path,
            output_path=args.operational_report_output,
        )
        print(f"Operational validation report written to: {report['output_path']}")


if __name__ == "__main__":
    main()
