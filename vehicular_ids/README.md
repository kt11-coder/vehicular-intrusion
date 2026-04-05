# Rule-Based Intrusion Detection System for Vehicular Communication (CAN Bus)

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![SQLite](https://img.shields.io/badge/SQLite-Persistence-green)
![CI](https://img.shields.io/badge/Tests-12%20passing-brightgreen)

Production-style CAN IDS prototype with deterministic rules, DBC signal decoding,
hybrid anomaly scoring, SQLite-backed incident storage, benchmark metrics,
authenticated Streamlit SOC dashboard, live replay / python-can ingestion, Docker
deployment, and CI tests.

## Core Capabilities

- Rule-based detection for flood, unknown-ID, replay, sequence, and invalid-value attacks.
- DBC-style decoding of payloads into `vehicle_speed`, `engine_rpm`, `throttle_pct`,
  `brake_flag`, `coolant_temp`, and `rolling_counter`.
- Hybrid statistical anomaly scoring on engineered traffic and decoded-signal features.
- Incident IDs, severity scores, deduplication, packet-count evidence, and alert windows.
- SQLite persistence for packet history and alert history.
- CSV alert export and benchmark scoring against labeled datasets.
- Authenticated Streamlit dashboard with SOC overview, incident queue, packet explorer,
  live replay stream, SQLite history, and policy views.
- Optional live CAN ingestion through `python-can`.

## Project Structure

```text
vehicular_ids/
|-- app/
|   `-- dashboard.py
|-- data/
|   |-- sample_can_data.csv
|   `-- vehicle_signals.dbc
|-- docs/
|   `-- ARCHITECTURE.md
|-- logs/
|   `-- .gitkeep
|-- reports/
|   `-- .gitkeep
|-- src/
|   |-- alert_system.py
|   |-- auth.py
|   |-- can_decoder.py
|   |-- evaluation.py
|   |-- feature_engineering.py
|   |-- hybrid_detector.py
|   |-- logging_setup.py
|   |-- pipeline.py
|   |-- preprocessing.py
|   |-- public_dataset_adapters.py
|   |-- rule_engine.py
|   |-- simulator.py
|   |-- storage.py
|   `-- streaming.py
|-- storage/
|   `-- .gitkeep
|-- tests/
|   `-- test_ids_pipeline.py
|-- utils/
|   `-- config.py
|-- .github/workflows/ci.yml
|-- .streamlit/config.toml
|-- .streamlit/secrets.example.toml
|-- .gitignore
|-- docker-compose.yml
|-- Dockerfile
|-- main.py
|-- requirements.txt
`-- README.md
```

## Setup

```bash
pip install -r requirements.txt
```

## Run the CLI Pipeline

```bash
python main.py --alerts-output reports/alerts_v2.csv --db-path storage/vehicular_ids.sqlite3
```

Generate calibrated thresholds and a deployment-readiness report:

```bash
python main.py \
  --dbc-path data/vehicle_signals.dbc \
  --calibrate-thresholds \
  --calibration-output reports/threshold_calibration.json \
  --operational-report \
  --operational-report-output reports/operational_validation_report.md
```

Rule-only mode:

```bash
python main.py --disable-hybrid
```

If `data/sample_can_data.csv` is missing or uses a legacy schema, the simulator
automatically regenerates a labeled synthetic dataset.

## Run the Streamlit Dashboard

```bash
streamlit run app/dashboard.py
```

Default demo login:

```text
username: admin
password: vehicular-ids-demo
```

To configure production credentials, copy `.streamlit/secrets.example.toml` to
`.streamlit/secrets.toml` and replace the values, or set these environment vars:

```text
VEHICULAR_IDS_AUTH_ENABLED=true
VEHICULAR_IDS_USER=<your-user>
VEHICULAR_IDS_PASSWORD=<your-password>
```

## Live CAN Ingestion

The dashboard's `Live Stream` tab supports:

- Synthetic replay batches from `data/sample_can_data.csv`
- Real bus polling through `python-can` when a CAN interface is available

For Linux SocketCAN, a typical interface setup is `vcan0` or `can0` with bus type
`socketcan`.

## Benchmark Evaluation

When the dataset includes a `ground_truth` column, the pipeline computes:

- accuracy
- precision
- recall
- F1 score
- false-positive rate
- per-attack recall

The bundled synthetic dataset includes labels for `normal`, `flood_attack`,
`replay_attack`, `unknown_id`, and `invalid_value`.

## Public Real-World Dataset Adapters

The project now includes converters for public benchmark formats:

- HCRL Car-Hacking / OTIDS style CSV files
- ROAD / candump style raw CAN logs with optional metadata intervals

Example:

```python
from src.public_dataset_adapters import convert_public_dataset

convert_public_dataset(
    source_path="path/to/Car_Hacking_Challenge.csv",
    dataset_format="hcrl",
    output_path="data/hcrl_canonical.csv",
)

convert_public_dataset(
    source_path="path/to/road.log",
    dataset_format="road",
    output_path="data/road_canonical.csv",
    metadata_path="path/to/metadata.json",
)
```

Then run:

```bash
python main.py --dataset data/hcrl_canonical.csv --dbc-path data/vehicle_signals.dbc --calibrate-thresholds
```

Primary sources:

- HCRL datasets: https://ocslab.hksecurity.net/Datasets
- ROAD dataset: https://zenodo.org/records/10462796
- Open DBC repository: https://github.com/commaai/opendbc

## Run Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Docker

```bash
docker build -t vehicular-ids .
docker run -p 8501:8501 vehicular-ids
```

Or with Compose:

```bash
docker compose up --build
```

Then open `http://localhost:8501`.

## Streamlit Community Cloud

1. Push this repository to GitHub.
2. Create a new app in Streamlit Community Cloud.
3. Set entrypoint to `app/dashboard.py`.
4. Add auth secrets from `.streamlit/secrets.example.toml`.
5. Deploy and share your public `*.streamlit.app` URL.

For a public read-only demo, set this secret/environment variable:

```text
VEHICULAR_IDS_PUBLIC_DEMO=true
```

Official docs:
https://docs.streamlit.io/deploy/streamlit-community-cloud/manage-your-app

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Notes for Real Vehicle/Fleet Use

This is now a strong production-style prototype, but before using it on an
actual vehicle network or fleet SOC, you should replace the demo DBC and
synthetic baseline with OEM/project-specific DBC files, known-good traffic
captures, interface-specific `python-can` settings, and environment-specific
threshold tuning.
