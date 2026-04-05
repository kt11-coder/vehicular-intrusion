"""Reusable IDS pipeline orchestration for CLI, dashboard, and tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pandas as pd

from src.alert_system import AlertSystem
from src.feature_engineering import engineer_features
from src.hybrid_detector import HybridAnomalyDetector
from src.logging_setup import setup_logging
from src.preprocessing import load_dataset, preprocess_can_data
from src.rule_engine import RuleEngine
from src.simulator import ensure_sample_dataset
from src.storage import IDSStorage
from utils.config import DEFAULT_DBC_PATH, SAMPLE_DATASET_PATH


LOGGER = setup_logging()


@dataclass
class PipelineResult:
    """Container with every stage output of a completed IDS run."""

    source: str
    raw_frame: pd.DataFrame
    processed_frame: pd.DataFrame
    feature_frame: pd.DataFrame
    alert_system: AlertSystem
    storage: Optional[IDSStorage] = None

    @property
    def alert_frame(self) -> pd.DataFrame:
        return self.alert_system.to_dataframe()

    @property
    def summary(self) -> dict:
        return self.alert_system.summary()


def run_ids_pipeline(
    dataset_path: Path | str = SAMPLE_DATASET_PATH,
    raw_frame: Optional[pd.DataFrame] = None,
    dbc_path: Path | str = DEFAULT_DBC_PATH,
    rule_engine: Optional[RuleEngine] = None,
    hybrid_detector: Optional[HybridAnomalyDetector] = None,
    storage: Optional[IDSStorage] = None,
    auto_generate_dataset: bool = True,
    enable_hybrid_detection: bool = True,
    persist_results: bool = False,
) -> PipelineResult:
    """Execute the full preprocessing, feature, detection, and alert pipeline."""
    if raw_frame is None:
        csv_path = Path(dataset_path)
        if auto_generate_dataset:
            ensure_sample_dataset(csv_path)
        loaded_frame = load_dataset(csv_path)
        source = str(csv_path)
    else:
        loaded_frame = raw_frame.copy()
        source = "uploaded_dataframe"

    processed_frame = preprocess_can_data(loaded_frame, dbc_path=dbc_path)
    feature_frame = engineer_features(processed_frame)

    engine = rule_engine or RuleEngine()
    alerts = engine.evaluate(feature_frame)

    if enable_hybrid_detection:
        detector = hybrid_detector or HybridAnomalyDetector()
        detector.fit(feature_frame)
        alerts.extend(detector.detect(feature_frame))

    alert_system = AlertSystem()
    alert_system.add_alerts(alerts)

    if persist_results and storage is not None:
        storage.save_packets(feature_frame)
        storage.save_alerts(alert_system.to_dataframe())

    summary = alert_system.summary()
    LOGGER.info(
        "Pipeline completed source=%s packets=%s alerts=%s impacted_packets=%s",
        source,
        len(feature_frame),
        summary["total_alerts"],
        summary["total_impacted_packets"],
    )

    return PipelineResult(
        source=source,
        raw_frame=loaded_frame,
        processed_frame=processed_frame,
        feature_frame=feature_frame,
        alert_system=alert_system,
        storage=storage,
    )
