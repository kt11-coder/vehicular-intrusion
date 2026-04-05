"""Generate deployment-readiness validation reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from src.calibration import calibrate_thresholds_from_dataset
from src.dbc_validator import validate_dbc_against_dataset, validate_dbc_file
from src.evaluation import evaluate_detection_performance
from src.pipeline import run_ids_pipeline
from utils.config import (
    DEFAULT_DB_PATH,
    DEFAULT_DBC_PATH,
    OPERATIONAL_REPORT_PATH,
    SAMPLE_DATASET_PATH,
)


def _status_line(passed: bool, label: str, detail: str) -> str:
    status = "PASS" if passed else "ACTION NEEDED"
    return f"- **{status}** | {label}: {detail}"


def generate_operational_report(
    dataset_path: Path | str = SAMPLE_DATASET_PATH,
    dbc_path: Path | str = DEFAULT_DBC_PATH,
    output_path: Path | str = OPERATIONAL_REPORT_PATH,
) -> Dict[str, Any]:
    """Run deployment checks and write a markdown readiness report."""
    dbc_report = validate_dbc_file(dbc_path)
    coverage_report = validate_dbc_against_dataset(dataset_path, dbc_path)
    calibration_report = calibrate_thresholds_from_dataset(
        dataset_path=dataset_path,
        dbc_path=dbc_path,
    )
    result = run_ids_pipeline(
        dataset_path=dataset_path,
        dbc_path=dbc_path,
        auto_generate_dataset=True,
    )
    metrics = evaluate_detection_performance(result.feature_frame, result.alert_frame)

    checks = [
        _status_line(
            dbc_report["valid"],
            "DBC parser",
            f"{dbc_report['message_count']} messages, {dbc_report['signal_count']} signals parsed.",
        ),
        _status_line(
            coverage_report["dbc_coverage_ratio"] >= 0.7,
            "DBC coverage",
            (
                f"{coverage_report['dbc_coverage_ratio']:.2%} of dataset CAN IDs are covered; "
                f"missing IDs: {coverage_report['missing_dataset_ids_in_dbc']}"
            ),
        ),
        _status_line(
            coverage_report["decode_success_ratio"] >= 0.95,
            "Signal decode success",
            f"{coverage_report['decode_success_ratio']:.2%} decode success on known IDs.",
        ),
        _status_line(
            bool(metrics.get("available")),
            "Benchmark labels",
            "Ground-truth labels found." if metrics.get("available") else "Ground-truth labels missing.",
        ),
        _status_line(
            metrics.get("precision", 0.0) >= 0.6 if metrics.get("available") else False,
            "Precision target",
            f"Precision={metrics.get('precision', 0.0):.4f}; target >= 0.6000",
        ),
        _status_line(
            metrics.get("recall", 0.0) >= 0.9 if metrics.get("available") else False,
            "Recall target",
            f"Recall={metrics.get('recall', 0.0):.4f}; target >= 0.9000",
        ),
        _status_line(
            metrics.get("false_positive_rate", 1.0) <= 0.25 if metrics.get("available") else False,
            "False-positive-rate guardrail",
            f"FPR={metrics.get('false_positive_rate', 1.0):.4f}; guardrail <= 0.2500",
        ),
    ]

    missing_real_world_items = [
        "Run this report on real CAN captures from the target vehicle/fleet.",
        "Replace the demo DBC with the OEM/project-specific DBC file.",
        "Tune thresholds from a clean baseline route and re-run calibration.",
        "Exercise a staging deployment against the actual CAN interface and logging stack.",
        "Review dashboard credentials, network exposure, and SQLite retention/backups before sharing externally.",
    ]

    markdown = "\n".join(
        [
            "# Vehicular IDS Operational Validation Report",
            "",
            f"- Dataset: `{Path(dataset_path)}`",
            f"- DBC: `{Path(dbc_path)}`",
            f"- SQLite path: `{Path(DEFAULT_DB_PATH)}`",
            "",
            "## Deployment Checks",
            "",
            *checks,
            "",
            "## Benchmark Metrics",
            "",
            f"- Accuracy: `{metrics.get('accuracy', 'N/A')}`",
            f"- Precision: `{metrics.get('precision', 'N/A')}`",
            f"- Recall: `{metrics.get('recall', 'N/A')}`",
            f"- F1 Score: `{metrics.get('f1_score', 'N/A')}`",
            f"- False Positive Rate: `{metrics.get('false_positive_rate', 'N/A')}`",
            f"- Per-Attack Recall: `{metrics.get('per_attack_recall', {})}`",
            "",
            "## Calibrated Threshold Recommendation",
            "",
            "```json",
            json.dumps(calibration_report["recommended_thresholds"], indent=2),
            "```",
            "",
            "## Real-World Deployment Actions Still Required",
            "",
            *[f"- {item}" for item in missing_real_world_items],
            "",
        ]
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(markdown, encoding="utf-8")

    return {
        "output_path": str(output_file),
        "dbc_report": dbc_report,
        "coverage_report": coverage_report,
        "calibration_report": calibration_report,
        "metrics": metrics,
        "checks": checks,
        "pending_real_world_actions": missing_real_world_items,
    }
