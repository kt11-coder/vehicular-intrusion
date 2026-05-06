"""Central configuration for the rule-based vehicular IDS project."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
LOG_DIR = PROJECT_ROOT / "logs"
DB_DIR = PROJECT_ROOT / "storage"
SAMPLE_DATASET_PATH = DATA_DIR / "sample_can_data.csv"
DEMO_DATASET_PATH = DATA_DIR / "sample_can_data_demo.csv"
DEFAULT_DBC_PATH = DATA_DIR / "vehicle_signals.dbc"
DEFAULT_ALERT_EXPORT_PATH = REPORTS_DIR / "alerts.csv"
DEFAULT_DB_PATH = DB_DIR / "vehicular_ids.sqlite3"
DEFAULT_LOG_PATH = LOG_DIR / "vehicular_ids.log"

REQUIRED_COLUMNS = {"timestamp", "message_id", "data_bytes", "speed"}
OPTIONAL_LABEL_COLUMN = "ground_truth"

WHITELISTED_MESSAGE_IDS = [
    "0x100",
    "0x101",
    "0x102",
    "0x200",
    "0x201",
    "0x300",
    "0x301",
]

UNKNOWN_MESSAGE_IDS = [
    "0x555",
    "0x666",
    "0x777",
    "0x7AB",
]

NORMAL_SPEED_RANGES = {
    "0x100": (0, 140),
    "0x101": (0, 140),
    "0x102": (0, 140),
    "0x200": (0, 160),
    "0x201": (0, 160),
    "0x300": (0, 130),
    "0x301": (0, 130),
}

ROLLING_FREQUENCY_WINDOW = "1s"
SEQUENCE_WINDOW_SIZE = 4
SEQUENCE_REPEAT_TIME_BUCKET = "500ms"

FLOOD_MESSAGES_PER_SECOND_THRESHOLD = 180
REPLAY_MIN_TIME_DIFF_SECONDS = 0.01
REPLAY_REPEAT_THRESHOLD = 3
SEQUENCE_REPEAT_THRESHOLD = 3
MAX_VALID_SPEED = 300.0
MIN_VALID_SPEED = 0.0

ANOMALY_SCORE_THRESHOLD = 0.72
INCIDENT_DEDUP_SECONDS = 5
SEVERITY_SCORE_BY_LEVEL = {
    "Low": 35,
    "Medium": 65,
    "High": 90,
}

DEMO_AUTH_USERNAME = "admin"
DEMO_AUTH_PASSWORD = "vehicular-ids-demo"
AUTH_USERNAME_ENV = "VEHICULAR_IDS_USER"
AUTH_PASSWORD_ENV = "VEHICULAR_IDS_PASSWORD"
AUTH_ENABLED_ENV = "VEHICULAR_IDS_AUTH_ENABLED"
PUBLIC_DEMO_MODE_ENV = "VEHICULAR_IDS_PUBLIC_DEMO"

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_UPLOAD_ROWS = 500_000

CALIBRATION_NORMAL_QUANTILE = 0.995
CALIBRATION_REPLAY_QUANTILE = 0.01
CALIBRATION_REPORT_PATH = REPORTS_DIR / "threshold_calibration.json"
OPERATIONAL_REPORT_PATH = REPORTS_DIR / "operational_validation_report.md"

SIMULATOR_SETTINGS = {
    "seed": 42,
    "normal_packets": 1000,
    "flood_packets": 260,
    "replay_packets": 80,
    "unknown_id_packets": 60,
    "invalid_speed_packets": 24,
}
