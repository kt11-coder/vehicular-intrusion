# Rule-Based Intrusion Detection System for Vehicular Communication (CAN Bus)

## Project Report

## 1. Abstract

Modern vehicles rely on the Controller Area Network (CAN) bus to exchange
messages among Electronic Control Units (ECUs). Although CAN is efficient and
widely deployed, its original design does not include strong built-in security
controls such as authentication or encryption. As a result, a compromised node
can inject, replay, flood, or manipulate CAN traffic and affect critical
vehicle functions.

This project presents a complete end-to-end Intrusion Detection System (IDS)
for vehicular CAN communication. The system combines deterministic rule-based
detection with a lightweight hybrid anomaly scoring layer. It supports
synthetic dataset generation, preprocessing, DBC-based payload decoding,
feature engineering, rule evaluation, incident aggregation, SQLite persistence,
benchmark evaluation, threshold calibration, and a Streamlit-based SOC-style
dashboard.

The final system successfully detects flood attacks, unknown ID injection,
replay attacks, sequence anomalies, and invalid signal values. On the bundled
labeled evaluation dataset, the system achieved an accuracy of `0.8511`,
precision of `0.6667`, recall of `1.0000`, F1-score of `0.8000`, and false
positive rate of `0.2120`.

## 2. Introduction

Vehicular networks are increasingly connected to external systems such as
infotainment modules, telematics units, mobile devices, and cloud platforms.
This connectivity improves functionality but also increases the attack surface.
Since CAN messages are broadcast and trust-based, an attacker with bus access
can impersonate legitimate ECUs and inject malicious frames without being
cryptographically challenged.

An IDS provides a practical defensive layer by monitoring traffic and raising
alerts when suspicious behavior is observed. For CAN environments, such an IDS
must be lightweight, interpretable, and efficient enough to analyze message
streams in near real time. This project addresses that need with a modular,
production-style prototype that is suitable for academic demonstration,
portfolio use, and further research development.

## 3. Problem Statement

The objective is to detect malicious or anomalous CAN bus behavior from traffic
logs or live streams using explicit security rules and supporting analytics.
The system must:

- process CAN datasets end to end
- detect multiple classes of attacks
- provide structured alerts with severity and evidence
- support dashboard-based investigation
- support future extension to real-world datasets and DBC files

## 4. Objectives

The project was designed with the following objectives:

- build a complete, modular CAN IDS pipeline
- generate realistic synthetic traffic with labeled attacks
- preprocess and normalize CAN traffic records
- decode message payloads using a DBC-style signal definition
- engineer features for frequency, timing, and sequence analysis
- implement rule-based attack detection
- add a hybrid anomaly detector for statistical deviation scoring
- store packets and incidents in SQLite
- visualize outputs through a Streamlit dashboard
- provide deployment, calibration, and operational validation tooling

## 5. Scope of the System

The implemented system supports:

- CAN CSV ingestion
- synthetic replay streaming
- optional `python-can` live bus ingestion
- DBC payload decoding
- event-level alerting with deduplication and incident IDs
- benchmark evaluation against labeled data
- threshold calibration from baseline traffic
- operational validation reporting
- local demo and public demo deployment preparation

The system does not claim full OEM production certification. Real-world
adoption would still require OEM-specific DBC files, real CAN captures,
vehicle-specific threshold tuning, integration testing, and deployment
hardening on the target environment.

## 6. System Architecture

The project follows a layered pipeline:

1. Data Ingestion
2. Preprocessing and Normalization
3. DBC Signal Decoding
4. Feature Engineering
5. Rule-Based Detection
6. Hybrid Anomaly Scoring
7. Incident Aggregation and Deduplication
8. SQLite Persistence and CSV Reporting
9. Dashboard Visualization and Investigation
10. Calibration and Operational Validation

Reference architecture is documented in:
`docs/ARCHITECTURE.md`

## 7. Project Structure

```text
vehicular_ids/
|-- app/
|   `-- dashboard.py
|-- data/
|   |-- sample_can_data.csv
|   `-- vehicle_signals.dbc
|-- docs/
|   |-- ARCHITECTURE.md
|   `-- PROJECT_REPORT.md
|-- logs/
|   `-- vehicular_ids.log
|-- reports/
|   |-- alerts_v2.csv
|   |-- operational_validation_report.md
|   `-- threshold_calibration.json
|-- src/
|   |-- alert_system.py
|   |-- auth.py
|   |-- calibration.py
|   |-- can_decoder.py
|   |-- dbc_validator.py
|   |-- demo_mode.py
|   |-- evaluation.py
|   |-- feature_engineering.py
|   |-- hybrid_detector.py
|   |-- logging_setup.py
|   |-- operational_report.py
|   |-- pipeline.py
|   |-- preprocessing.py
|   |-- public_dataset_adapters.py
|   |-- rule_engine.py
|   |-- simulator.py
|   |-- storage.py
|   `-- streaming.py
|-- tests/
|   `-- test_ids_pipeline.py
|-- utils/
|   `-- config.py
|-- main.py
|-- requirements.txt
`-- README.md
```

## 8. Dataset Design

### 8.1 Synthetic Dataset

The project includes a synthetic dataset generator that creates realistic CAN
traffic with the following columns:

- `timestamp`
- `message_id`
- `data_bytes`
- `speed`
- `ground_truth`

### 8.2 Traffic Categories

The synthetic generator produces:

- normal traffic
- flood attack traffic
- replay attack traffic
- unknown ID injection traffic
- invalid value traffic

### 8.3 Dataset Size

The current bundled dataset contains:

- `1000` normal packets
- `260` flood packets
- `80` replay packets
- `60` unknown ID packets
- `24` invalid value packets

Total packets: `1424`

### 8.4 Public Dataset Support

The system now supports conversion of public real-world benchmark datasets:

- HCRL Car-Hacking / OTIDS style CSV logs
- ROAD / candump style logs with optional metadata windows

This makes the platform easier to validate against real CAN traffic traces
without redesigning the internal schema.

## 9. Preprocessing Stage

The preprocessing module performs:

- schema validation
- timestamp conversion to datetime
- chronological sorting
- duplicate removal
- missing-value handling
- CAN ID normalization
- payload normalization to fixed hex strings
- DBC-based signal decoding

The decoded signals currently include:

- `vehicle_speed`
- `engine_rpm`
- `throttle_pct`
- `brake_flag`
- `coolant_temp`
- `rolling_counter`

This step produces a clean and enriched dataframe for downstream feature
engineering.

## 10. Feature Engineering

The feature engineering module derives traffic and payload behavior features,
including:

- `messages_per_second`
- `time_diff`
- `rolling_frequency_per_id`
- `sequence_signature`
- `sequence_repeat_count`
- `payload_changed`
- `payload_entropy`
- `rolling_speed_std_per_id`
- `speed_signal_delta`

These features support both deterministic rules and anomaly scoring.

## 11. Detection Logic

### 11.1 Rule-Based Detection

The class `RuleEngine` implements the following rules:

1. Flood Attack
   Triggered when message rate exceeds the configured threshold.

2. Unknown ID
   Triggered when a CAN ID is not present in the whitelist.

3. Replay Attack
   Triggered when the same payload repeats for the same CAN ID with very small
   inter-arrival times multiple times in succession.

4. Sequence Anomaly
   Triggered when identical CAN ID sequences repeat excessively within short
   time windows.

5. Invalid Value
   Triggered when the observed or decoded speed falls outside physical bounds.

### 11.2 Hybrid Anomaly Detector

In addition to explicit rules, the system includes a lightweight hybrid anomaly
detector that:

- learns robust baseline statistics from normal or warm-up traffic
- computes robust deviation scores across engineered features
- generates `Hybrid ML Anomaly` incidents when anomaly score thresholds are
  exceeded

This hybrid layer improves sensitivity to suspicious behavior that may not
fully satisfy a hand-crafted rule.

## 12. Alert and Incident Model

Alerts are aggregated into incident-level records. Each incident includes:

- `incident_id`
- `timestamp`
- `alert_type`
- `severity`
- `severity_score`
- `message_id`
- `description`
- `packet_count`
- `window_start`
- `window_end`
- `sample_payload`
- optional `anomaly_score`

The alert system also performs short-window deduplication so repeated alerts do
not overwhelm the analyst.

## 13. Dashboard Design

The Streamlit dashboard is designed as a lightweight SOC console with the
following sections:

- `SOC Overview`
- `Incident Queue`
- `Packet Explorer`
- `Live Stream`
- `SQLite History`
- `Rules & Policy`

### Dashboard Highlights

- summary KPIs
- frequency and incident distribution charts
- top CAN ID activity view
- downloadable incident CSV
- simulated live replay mode
- SQLite-backed historical views
- public-demo mode for safe external showcasing

## 14. Persistence and Reporting

The system stores operational data in SQLite:

- packets table
- alerts table

It also exports:

- alert CSV reports
- threshold calibration JSON
- operational validation markdown reports

This improves usability beyond a temporary notebook-style prototype and makes
the system more suitable for repeated demonstrations and analysis.

## 15. Security and Hardening Measures

Several practical hardening measures were added:

- authentication support for the dashboard
- public-demo mode for safer public links
- input size and row limits for uploaded datasets
- logging to file for diagnostics
- DBC validation support
- operational readiness reporting
- CI workflow and automated tests

These changes improve reliability and reduce accidental misuse during demos.

## 16. Calibration and Validation

The project includes a threshold calibration module that estimates rule
thresholds from baseline traffic. Current recommended values from the bundled
sample are:

- flood threshold: `53`
- replay minimum time difference: `0.006449 s`
- replay repeat threshold: `3`
- sequence repeat threshold: `3`
- maximum valid speed: `179.61`
- anomaly score threshold: `0.9978`

Operational validation also checks:

- DBC parsing
- DBC-to-dataset coverage
- decode success rate
- benchmark metrics
- false-positive-rate guardrail

## 17. Experimental Results

Using the current labeled sample dataset, the measured results are:

- Accuracy: `0.8511`
- Precision: `0.6667`
- Recall: `1.0000`
- F1-score: `0.8000`
- False Positive Rate: `0.2120`

Per-attack recall on the bundled labeled dataset:

- Flood attack: `1.0`
- Invalid value: `1.0`
- Replay attack: `1.0`
- Unknown ID: `1.0`

The DBC validation status is:

- DBC parser: passed
- Signal decode success on known IDs: `100%`
- DBC coverage on current sample: `63.64%`

The coverage is below full coverage because injected unknown malicious IDs are
intentionally not represented in the demo DBC.

## 18. Testing Performed

The project includes automated tests for:

- preprocessing and normalization
- DBC decoding
- rule detection behavior
- pipeline execution
- benchmark evaluation
- SQLite storage
- authentication helpers
- streaming helpers
- public dataset adapters
- operational report and calibration generation

Current test status:

- `12` tests passed successfully

## 19. Deployment Readiness

The project is deployment-ready in the following sense:

- it runs locally
- it has a working web dashboard
- it can be deployed on Streamlit Community Cloud
- it has Docker and Docker Compose support
- it includes CI configuration
- it has public-demo support

For academic submission, portfolio use, and demonstrations, the project is
ready.

## 20. Limitations

Despite being a strong production-style prototype, some real-world limitations
remain:

- the bundled DBC is a demo DBC, not an OEM DBC
- the main dataset is synthetic, even though public benchmark adapters are supported
- live CAN validation depends on access to a real interface
- thresholds still need per-vehicle calibration for production environments
- SQLite is suitable for demo and prototype usage, but large fleet deployments
  may require PostgreSQL or a larger data platform

## 21. Future Enhancements

Future improvements may include:

- OEM-specific DBC integration
- validation on real fleet traffic
- PostgreSQL backend
- role-based access control
- richer signal-level physical consistency checks
- alert acknowledgement workflow
- automated report generation in PDF format
- additional ML models for adaptive anomaly detection

## 22. Conclusion

This project successfully delivers a complete end-to-end IDS for vehicular CAN
communication. It goes beyond a basic classroom prototype by integrating
deterministic rules, hybrid anomaly scoring, DBC decoding, persistence,
calibration, validation, deployment assets, and a full dashboard experience.

The final system is suitable as:

- a strong academic project
- a professional GitHub portfolio project
- a cybersecurity and AI systems demonstration
- a foundation for further vehicular security research

In summary, the project is complete, functional, modular, and well positioned
as a high-quality production-style prototype.

## 23. References

- CAN bus security concepts and vehicular IDS literature
- HCRL Car-Hacking Dataset: https://ocslab.hksecurity.net/Datasets
- ROAD Dataset: https://zenodo.org/records/10462796
- Open DBC repository: https://github.com/commaai/opendbc
- Streamlit Community Cloud documentation: https://docs.streamlit.io/
