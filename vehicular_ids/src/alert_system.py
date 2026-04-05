"""Alert storage and reporting utilities for the CAN IDS pipeline."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any, Dict, Iterable, List

import pandas as pd

from utils.config import INCIDENT_DEDUP_SECONDS, SEVERITY_SCORE_BY_LEVEL


class AlertSystem:
    """Store IDS alerts as structured records and expose summary views."""

    def __init__(self, dedup_seconds: int = INCIDENT_DEDUP_SECONDS) -> None:
        self._alerts: List[Dict[str, Any]] = []
        self.dedup_window = timedelta(seconds=dedup_seconds)
        self._dedup_index: Dict[str, pd.Timestamp] = {}

    @property
    def alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    @staticmethod
    def _normalize_timestamp(value: Any) -> pd.Timestamp:
        parsed = pd.to_datetime(value, errors="coerce")
        if pd.isna(parsed):
            return pd.Timestamp.utcnow()
        return pd.Timestamp(parsed)

    def _incident_id_for(self, alert: Dict[str, Any]) -> str:
        window_start = self._normalize_timestamp(
            alert.get("window_start", alert["timestamp"])
        ).floor(f"{max(int(self.dedup_window.total_seconds()), 1)}s")
        fingerprint = "|".join(
            [
                str(alert["alert_type"]),
                str(alert["message_id"]),
                str(window_start),
                str(alert.get("sample_payload", "")),
            ]
        )
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16].upper()

    def _should_drop_duplicate(self, alert: Dict[str, Any]) -> bool:
        key = str(alert["incident_id"])
        current_time = self._normalize_timestamp(alert["timestamp"])
        previous_time = self._dedup_index.get(key)
        if previous_time is not None and current_time - previous_time <= self.dedup_window:
            return True

        self._dedup_index[key] = current_time
        return False

    def add_alert(self, alert: Dict[str, Any]) -> None:
        required_fields = {"timestamp", "alert_type", "severity", "message_id"}
        missing_fields = required_fields.difference(alert)
        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(f"Alert record is missing required fields: {missing}")

        enriched_alert = dict(alert)
        enriched_alert["timestamp"] = self._normalize_timestamp(alert["timestamp"])
        enriched_alert.setdefault("window_start", enriched_alert["timestamp"])
        enriched_alert.setdefault("window_end", enriched_alert["timestamp"])
        enriched_alert.setdefault("packet_count", 1)
        enriched_alert.setdefault("sample_payload", "")
        base_score = SEVERITY_SCORE_BY_LEVEL.get(str(enriched_alert["severity"]), 50)
        evidence_boost = min(int(enriched_alert.get("packet_count", 1)), 50)
        anomaly_score = float(enriched_alert.get("anomaly_score", 0.0) or 0.0)
        enriched_alert["severity_score"] = min(
            100,
            int(round(base_score + 0.2 * evidence_boost + 10.0 * anomaly_score)),
        )
        enriched_alert["incident_id"] = self._incident_id_for(enriched_alert)

        if self._should_drop_duplicate(enriched_alert):
            return

        self._alerts.append(enriched_alert)

    def add_alerts(self, alerts: Iterable[Dict[str, Any]]) -> None:
        for alert in alerts:
            self.add_alert(alert)

    def clear(self) -> None:
        self._alerts.clear()
        self._dedup_index.clear()

    def to_dataframe(self) -> pd.DataFrame:
        columns = [
            "incident_id",
            "timestamp",
            "alert_type",
            "severity",
            "severity_score",
            "message_id",
            "description",
            "packet_count",
            "window_start",
            "window_end",
            "sample_payload",
            "anomaly_score",
        ]

        if not self._alerts:
            return pd.DataFrame(columns=columns)

        alert_frame = pd.DataFrame(self._alerts)
        alert_frame["timestamp"] = pd.to_datetime(alert_frame["timestamp"])
        for column in columns:
            if column not in alert_frame.columns:
                alert_frame[column] = pd.NA
        return alert_frame.sort_values("timestamp", kind="stable").reset_index(drop=True)

    def summary(self) -> Dict[str, Any]:
        alert_frame = self.to_dataframe()
        if alert_frame.empty:
            return {
                "total_alerts": 0,
                "total_impacted_packets": 0,
                "alerts_by_type": {},
                "alerts_by_severity": {},
            }

        return {
            "total_alerts": int(len(alert_frame)),
            "total_impacted_packets": int(
                alert_frame.get("packet_count", pd.Series(dtype="float64"))
                .fillna(1)
                .sum()
            ),
            "alerts_by_type": alert_frame["alert_type"].value_counts().to_dict(),
            "alerts_by_severity": alert_frame["severity"].value_counts().to_dict(),
        }

    def export_csv(self, output_path: str) -> str:
        self.to_dataframe().to_csv(output_path, index=False)
        return output_path
