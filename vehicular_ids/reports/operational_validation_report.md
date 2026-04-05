# Vehicular IDS Operational Validation Report

- Dataset: `C:\Users\KARTIK SARAF\OneDrive\Desktop\vehicular intrusion\vehicular_ids\data\sample_can_data.csv`
- DBC: `C:\Users\KARTIK SARAF\OneDrive\Desktop\vehicular intrusion\vehicular_ids\data\vehicle_signals.dbc`
- SQLite path: `C:\Users\KARTIK SARAF\OneDrive\Desktop\vehicular intrusion\vehicular_ids\storage\vehicular_ids.sqlite3`

## Deployment Checks

- **PASS** | DBC parser: 7 messages, 42 signals parsed.
- **ACTION NEEDED** | DBC coverage: 63.64% of dataset CAN IDs are covered; missing IDs: ['0x555', '0x666', '0x777', '0x7AB']
- **PASS** | Signal decode success: 100.00% decode success on known IDs.
- **PASS** | Benchmark labels: Ground-truth labels found.
- **PASS** | Precision target: Precision=0.6667; target >= 0.6000
- **PASS** | Recall target: Recall=1.0000; target >= 0.9000
- **PASS** | False-positive-rate guardrail: FPR=0.2120; guardrail <= 0.2500

## Benchmark Metrics

- Accuracy: `0.8511`
- Precision: `0.6667`
- Recall: `1.0`
- F1 Score: `0.8`
- False Positive Rate: `0.212`
- Per-Attack Recall: `{'flood_attack': 1.0, 'invalid_value': 1.0, 'replay_attack': 1.0, 'unknown_id': 1.0}`

## Calibrated Threshold Recommendation

```json
{
  "flood_threshold": 53,
  "replay_min_time_diff_seconds": 0.006449,
  "replay_repeat_threshold": 3,
  "sequence_repeat_threshold": 3,
  "max_valid_speed": 179.61,
  "anomaly_score_threshold": 0.9978,
  "whitelist": [
    "0x100",
    "0x101",
    "0x102",
    "0x200",
    "0x201",
    "0x300",
    "0x301"
  ]
}
```

## Real-World Deployment Actions Still Required

- Run this report on real CAN captures from the target vehicle/fleet.
- Replace the demo DBC with the OEM/project-specific DBC file.
- Tune thresholds from a clean baseline route and re-run calibration.
- Exercise a staging deployment against the actual CAN interface and logging stack.
- Review dashboard credentials, network exposure, and SQLite retention/backups before sharing externally.
