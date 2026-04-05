# System Architecture

```mermaid
flowchart LR
    A[CAN CSV Upload / Synthetic Replay / python-can Bus] --> B[Preprocessing + DBC Decoder]
    B --> C[Feature Engineering]
    C --> D[Rule Engine]
    C --> E[Hybrid Anomaly Detector]
    D --> F[Alert System + Incident IDs + Dedup]
    E --> F
    F --> G[(SQLite Storage)]
    F --> H[CSV Reports]
    C --> I[Benchmark Evaluation + Threshold Calibration]
    I --> J[Operational Validation Report]
    G --> K[Streamlit SOC Dashboard]
    F --> K
    C --> K
```

## Runtime Modes

- **Local analyst mode:** auth on, persistence on, full storage controls visible.
- **Public demo mode:** set `VEHICULAR_IDS_PUBLIC_DEMO=true`; auth is disabled,
  persistence defaults to read-only, and destructive storage controls are hidden.
- **Live bus mode:** use the dashboard `Live Stream` tab with a python-can
  interface such as `vcan0` / `socketcan`.
