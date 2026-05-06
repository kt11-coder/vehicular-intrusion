"""Streamlit SOC-style dashboard for CAN IDS monitoring and investigation."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any, Mapping

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.auth import auth_is_enabled, verify_credentials
from src.demo_mode import public_demo_mode_enabled
from src.evaluation import evaluate_detection_performance
from src.pipeline import PipelineResult, run_ids_pipeline
from src.preprocessing import normalize_message_id
from src.rule_engine import RuleEngine
from src.simulator import save_current_demo_dataset
from src.storage import IDSStorage
from src.streaming import CsvReplayStreamReader, PythonCANStreamReader
from utils.config import (
    DEMO_DATASET_PATH,
    DEFAULT_DB_PATH,
    FLOOD_MESSAGES_PER_SECOND_THRESHOLD,
    MAX_UPLOAD_BYTES,
    MAX_VALID_SPEED,
    REPLAY_MIN_TIME_DIFF_SECONDS,
    REPLAY_REPEAT_THRESHOLD,
    SEQUENCE_REPEAT_THRESHOLD,
    WHITELISTED_MESSAGE_IDS,
)


st.set_page_config(page_title="Vehicular IDS Dashboard", layout="wide")


def safe_secrets() -> Mapping[str, Any]:
    try:
        return st.secrets
    except Exception:
        return {}


def require_login() -> None:
    secrets = safe_secrets()
    if not auth_is_enabled(secrets):
        return

    if st.session_state.get("authenticated"):
        return

    st.title("Vehicular IDS Dashboard")
    st.caption("Authenticated access is required to view the CAN SOC console.")

    with st.form("vehicular_ids_login"):
        username = st.text_input("Username", value="")
        password = st.text_input("Password", value="", type="password")
        submitted = st.form_submit_button("Sign in", use_container_width=True)

    if submitted and verify_credentials(username, password, secrets):
        st.session_state["authenticated"] = True
        st.rerun()

    if submitted:
        st.error("Invalid username or password.")
    else:
        st.info("Demo credentials default to admin / vehicular-ids-demo unless overridden by secrets or env vars.")
    st.stop()


def parse_whitelist(raw_whitelist: str) -> set[str]:
    parsed = {
        normalize_message_id(token.strip())
        for token in raw_whitelist.replace("\n", ",").split(",")
        if token.strip()
    }
    return parsed or set(WHITELISTED_MESSAGE_IDS)


def build_rule_engine(
    flood_threshold: int,
    replay_time_diff: float,
    replay_repeat_threshold: int,
    sequence_repeat_threshold: int,
    max_valid_speed: float,
    whitelist_text: str,
) -> RuleEngine:
    return RuleEngine(
        whitelist=parse_whitelist(whitelist_text),
        flood_threshold=flood_threshold,
        replay_min_time_diff_seconds=replay_time_diff,
        replay_repeat_threshold=replay_repeat_threshold,
        sequence_repeat_threshold=sequence_repeat_threshold,
        max_valid_speed=max_valid_speed,
    )


@st.cache_resource(show_spinner=False)
def get_storage() -> IDSStorage:
    return IDSStorage(DEFAULT_DB_PATH)


def get_demo_dataset_path() -> Path:
    demo_path = Path(st.session_state.get("demo_dataset_path", DEMO_DATASET_PATH))
    if "demo_dataset_path" not in st.session_state or not demo_path.exists():
        demo_path = save_current_demo_dataset(DEMO_DATASET_PATH)
        st.session_state["demo_dataset_path"] = str(demo_path)
    return demo_path


def rebuild_replay_reader() -> None:
    demo_dataset_path = get_demo_dataset_path()
    st.session_state["replay_reader"] = CsvReplayStreamReader(
        dataset_path=demo_dataset_path,
        batch_size=120,
        replay_delay_seconds=0.0,
    )


def initialize_stream_state() -> None:
    if "replay_reader" not in st.session_state:
        rebuild_replay_reader()
    if "stream_frame" not in st.session_state:
        st.session_state["stream_frame"] = pd.DataFrame()


def run_current_pipeline(
    uploaded_file: Any,
    rule_engine: RuleEngine,
    persist_results: bool,
) -> PipelineResult:
    storage = get_storage()
    if uploaded_file is None:
        demo_dataset_path = get_demo_dataset_path()
        return run_ids_pipeline(
            dataset_path=demo_dataset_path,
            rule_engine=rule_engine,
            storage=storage,
            persist_results=persist_results,
        )

    csv_bytes = uploaded_file.getvalue()
    if len(csv_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"Uploaded file exceeds {MAX_UPLOAD_BYTES} bytes. "
            "Use a smaller file or raise MAX_UPLOAD_BYTES in config.py."
        )
    csv_text = csv_bytes.decode("utf-8")
    raw_frame = pd.read_csv(io.StringIO(csv_text))
    return run_ids_pipeline(
        raw_frame=raw_frame,
        rule_engine=rule_engine,
        storage=storage,
        persist_results=persist_results,
    )


def reset_demo_session() -> None:
    if "replay_reader" in st.session_state:
        st.session_state["replay_reader"].reset()
    st.session_state["stream_frame"] = pd.DataFrame()


def render_sidebar(is_public_demo: bool) -> tuple[Any, RuleEngine, int, bool, bool, bool]:
    st.sidebar.header("Data Source")
    uploaded_file = st.sidebar.file_uploader("Upload CAN CSV", type=["csv"])
    persist_results = st.sidebar.toggle(
        "Persist packets and alerts to SQLite",
        value=not is_public_demo,
        disabled=is_public_demo,
        help=(
            "Disabled in public-demo mode so shared users do not mutate server-side "
            "history."
            if is_public_demo
            else None
        ),
    )
    regenerate_sample = st.sidebar.button("Refresh current-time demo sample")
    reset_session = st.sidebar.button("Reset demo session")

    if is_public_demo:
        st.sidebar.info(
            "Public demo mode is enabled: login is disabled, persistence defaults to "
            "read-only, and destructive storage actions are hidden."
        )

    st.sidebar.header("Rule Tuning")
    flood_threshold = st.sidebar.slider(
        "Flood threshold (packets/sec)",
        min_value=20,
        max_value=1000,
        value=FLOOD_MESSAGES_PER_SECOND_THRESHOLD,
        step=10,
    )
    replay_time_diff = st.sidebar.slider(
        "Replay min time-diff (sec)",
        min_value=0.001,
        max_value=0.100,
        value=float(REPLAY_MIN_TIME_DIFF_SECONDS),
        step=0.001,
        format="%.3f",
    )
    replay_repeat_threshold = st.sidebar.slider(
        "Replay repeat count",
        min_value=2,
        max_value=10,
        value=REPLAY_REPEAT_THRESHOLD,
        step=1,
    )
    sequence_repeat_threshold = st.sidebar.slider(
        "Sequence repeat threshold",
        min_value=2,
        max_value=20,
        value=SEQUENCE_REPEAT_THRESHOLD,
        step=1,
    )
    max_valid_speed = st.sidebar.slider(
        "Max valid speed",
        min_value=100,
        max_value=500,
        value=int(MAX_VALID_SPEED),
        step=10,
    )
    whitelist_text = st.sidebar.text_area(
        "Whitelisted CAN IDs",
        value=", ".join(WHITELISTED_MESSAGE_IDS),
        height=120,
    )

    rule_engine = build_rule_engine(
        flood_threshold=flood_threshold,
        replay_time_diff=replay_time_diff,
        replay_repeat_threshold=replay_repeat_threshold,
        sequence_repeat_threshold=sequence_repeat_threshold,
        max_valid_speed=float(max_valid_speed),
        whitelist_text=whitelist_text,
    )

    return (
        uploaded_file,
        rule_engine,
        flood_threshold,
        persist_results,
        regenerate_sample,
        reset_session,
    )


def render_frequency_chart(feature_frame: pd.DataFrame, flood_threshold: int) -> None:
    series = (
        feature_frame.groupby(feature_frame["timestamp"].dt.floor("s"))
        .size()
        .sort_index()
    )
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(series.index, series.values, color="#2563EB", linewidth=2)
    ax.axhline(
        flood_threshold,
        color="#DC2626",
        linestyle="--",
        linewidth=1.4,
        label=f"Flood threshold {flood_threshold}",
    )
    ax.set_title("CAN Packet Frequency")
    ax.set_xlabel("Time")
    ax.set_ylabel("Packets/sec")
    ax.grid(True, alpha=0.25)
    ax.legend(loc="upper right")
    fig.autofmt_xdate()
    st.pyplot(fig, use_container_width=True)
    plt.close(fig)


def render_alert_distribution(alert_frame: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    if alert_frame.empty:
        ax.text(0.5, 0.5, "No alerts", ha="center", va="center")
        ax.set_axis_off()
    else:
        counts = alert_frame["alert_type"].value_counts().sort_values(ascending=True)
        ax.barh(counts.index, counts.values, color="#DC2626")
        ax.set_title("Incident Count by Type")
        ax.set_xlabel("Count")
        ax.grid(axis="x", alpha=0.25)
    st.pyplot(fig, use_container_width=True)
    plt.close(fig)


def render_top_message_ids(feature_frame: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    top_ids = feature_frame["message_id"].value_counts().head(10).sort_values()
    ax.barh(top_ids.index, top_ids.values, color="#16A34A")
    ax.set_title("Top Talker CAN IDs")
    ax.set_xlabel("Packets")
    ax.grid(axis="x", alpha=0.25)
    st.pyplot(fig, use_container_width=True)
    plt.close(fig)


def render_overview_tab(result: PipelineResult, flood_threshold: int) -> None:
    summary = result.summary
    metrics = evaluate_detection_performance(result.feature_frame, result.alert_frame)

    metric_cols = st.columns(6)
    metric_cols[0].metric("Packets", f"{len(result.feature_frame):,}")
    metric_cols[1].metric("Incidents", f"{summary['total_alerts']:,}")
    metric_cols[2].metric("Impacted Packets", f"{summary['total_impacted_packets']:,}")
    metric_cols[3].metric("Precision", f"{metrics.get('precision', 0.0):.3f}" if metrics.get("available") else "N/A")
    metric_cols[4].metric("Recall", f"{metrics.get('recall', 0.0):.3f}" if metrics.get("available") else "N/A")
    metric_cols[5].metric("F1", f"{metrics.get('f1_score', 0.0):.3f}" if metrics.get("available") else "N/A")

    left, right = st.columns(2)
    with left:
        render_frequency_chart(result.feature_frame, flood_threshold)
    with right:
        render_alert_distribution(result.alert_frame)
    render_top_message_ids(result.feature_frame)

    if metrics.get("available"):
        st.subheader("Benchmark Evaluation")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "accuracy": metrics["accuracy"],
                        "precision": metrics["precision"],
                        "recall": metrics["recall"],
                        "f1_score": metrics["f1_score"],
                        "false_positive_rate": metrics["false_positive_rate"],
                        "true_positive": metrics["true_positive"],
                        "false_positive": metrics["false_positive"],
                        "true_negative": metrics["true_negative"],
                        "false_negative": metrics["false_negative"],
                    }
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
        if metrics["per_attack_recall"]:
            st.dataframe(
                pd.DataFrame(
                    [
                        {"attack_type": key, "recall": value}
                        for key, value in metrics["per_attack_recall"].items()
                    ]
                ),
                hide_index=True,
                use_container_width=True,
            )


def render_alerts_tab(result: PipelineResult) -> None:
    st.subheader("Active Incident Queue")
    alert_frame = result.alert_frame.copy()
    if alert_frame.empty:
        st.success("No incidents detected.")
        return

    left, right = st.columns(2)
    with left:
        selected_types = st.multiselect(
            "Alert types",
            sorted(alert_frame["alert_type"].dropna().unique().tolist()),
            default=sorted(alert_frame["alert_type"].dropna().unique().tolist()),
        )
    with right:
        selected_severities = st.multiselect(
            "Severity",
            sorted(alert_frame["severity"].dropna().unique().tolist()),
            default=sorted(alert_frame["severity"].dropna().unique().tolist()),
        )

    filtered = alert_frame.loc[
        alert_frame["alert_type"].isin(selected_types)
        & alert_frame["severity"].isin(selected_severities)
    ].sort_values(["severity_score", "timestamp"], ascending=[False, False])

    for column in ["timestamp", "window_start", "window_end"]:
        if column in filtered.columns:
            filtered[column] = filtered[column].astype(str)

    st.dataframe(filtered, hide_index=True, use_container_width=True, height=500)
    st.download_button(
        "Download filtered incidents CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="vehicular_ids_incidents.csv",
        mime="text/csv",
    )


def render_packets_tab(result: PipelineResult) -> None:
    st.subheader("Packet Explorer")
    packet_frame = result.feature_frame.copy()
    message_ids = sorted(packet_frame["message_id"].dropna().unique().tolist())
    selected_ids = st.multiselect(
        "Message IDs",
        message_ids,
        default=message_ids[: min(6, len(message_ids))],
    )
    packet_view = packet_frame.loc[packet_frame["message_id"].isin(selected_ids)].copy()
    for column in ["timestamp", "second_bucket", "sequence_time_bucket"]:
        if column in packet_view.columns:
            packet_view[column] = packet_view[column].astype(str)
    st.dataframe(
        packet_view.sort_values("timestamp", ascending=False).head(1500),
        hide_index=True,
        use_container_width=True,
        height=520,
    )


def render_stream_tab(rule_engine: RuleEngine, persist_results: bool) -> None:
    st.subheader("Live Ingestion Console")
    initialize_stream_state()
    storage = get_storage()

    csv_col, can_col = st.columns(2)

    with csv_col:
        st.markdown("**Synthetic Replay Stream**")
        if st.button("Process next replay batch", use_container_width=True):
            batch = st.session_state["replay_reader"].next_batch()
            stream_frame = pd.concat(
                [st.session_state["stream_frame"], batch],
                ignore_index=True,
            )
            st.session_state["stream_frame"] = stream_frame.tail(3000)
        if st.button("Reset replay stream", use_container_width=True):
            st.session_state["replay_reader"].reset()
            st.session_state["stream_frame"] = pd.DataFrame()

    with can_col:
        st.markdown("**python-can Live Bus Read**")
        channel = st.text_input("CAN channel", value="vcan0")
        bustype = st.text_input("Bus type", value="socketcan")
        reader = PythonCANStreamReader(channel=channel, bustype=bustype)
        if not reader.is_available:
            st.warning("python-can is not installed in this environment; replay mode remains available.")
        elif st.button("Read live CAN batch", use_container_width=True):
            try:
                live_batch = reader.read_batch(max_messages=200, timeout_seconds=0.03)
                if live_batch.empty:
                    st.info("No CAN frames received in this polling window.")
                else:
                    st.session_state["stream_frame"] = pd.concat(
                        [st.session_state["stream_frame"], live_batch],
                        ignore_index=True,
                    ).tail(3000)
            except Exception as error:
                st.error(f"Live CAN read failed: {error}")
            finally:
                reader.close()

    stream_frame = st.session_state["stream_frame"]
    if stream_frame.empty:
        st.info("No streamed packets buffered yet.")
        return

    stream_result = run_ids_pipeline(
        raw_frame=stream_frame,
        rule_engine=rule_engine,
        storage=storage,
        persist_results=persist_results,
    )
    stream_cols = st.columns(4)
    stream_cols[0].metric("Buffered Packets", f"{len(stream_result.feature_frame):,}")
    stream_cols[1].metric("Stream Incidents", f"{stream_result.summary['total_alerts']:,}")
    stream_cols[2].metric("Impacted Packets", f"{stream_result.summary['total_impacted_packets']:,}")
    stream_cols[3].metric("Last Packet", str(stream_result.feature_frame["timestamp"].max()))
    render_frequency_chart(stream_result.feature_frame, rule_engine.flood_threshold)
    st.dataframe(
        stream_result.alert_frame.sort_values("timestamp", ascending=False),
        hide_index=True,
        use_container_width=True,
        height=360,
    )


def render_storage_tab(is_public_demo: bool) -> None:
    st.subheader("Persisted SQLite History")
    storage = get_storage()
    alerts = storage.fetch_alerts(limit=1000)
    packets = storage.fetch_packets(limit=1000)

    left, right = st.columns(2)
    with left:
        st.metric("Stored Incidents", f"{len(alerts):,}")
    with right:
        st.metric("Stored Packets", f"{len(packets):,}")

    st.markdown("**Recent persisted incidents**")
    st.dataframe(alerts, hide_index=True, use_container_width=True, height=380)
    st.markdown("**Recent persisted packets**")
    st.dataframe(packets, hide_index=True, use_container_width=True, height=380)

    if is_public_demo:
        st.caption("Public-demo mode hides destructive storage actions.")
        return

    if st.button("Clear SQLite history", type="secondary"):
        storage.clear()
        st.success("Storage cleared.")
        st.rerun()


def render_rules_tab(rule_engine: RuleEngine) -> None:
    st.subheader("Active Detection Policy")
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Rule": "Flood Attack",
                    "Logic": "messages_per_second > threshold",
                    "Threshold": rule_engine.flood_threshold,
                    "Severity": "High",
                },
                {
                    "Rule": "Unknown ID",
                    "Logic": "message_id not in whitelist",
                    "Threshold": f"{len(rule_engine.whitelist)} IDs",
                    "Severity": "High",
                },
                {
                    "Rule": "Replay Attack",
                    "Logic": "same payload repeated under min time gap",
                    "Threshold": (
                        f"< {rule_engine.replay_min_time_diff_seconds:.3f}s "
                        f"for {rule_engine.replay_repeat_threshold}+ repeats"
                    ),
                    "Severity": "High",
                },
                {
                    "Rule": "Sequence Anomaly",
                    "Logic": "repeated identical ID sequence in short windows",
                    "Threshold": f">{rule_engine.sequence_repeat_threshold} repeats",
                    "Severity": "Medium",
                },
                {
                    "Rule": "Invalid Value",
                    "Logic": "speed or decoded_speed outside physical bounds",
                    "Threshold": f"{rule_engine.min_valid_speed} to {rule_engine.max_valid_speed}",
                    "Severity": "Medium",
                },
                {
                    "Rule": "Hybrid ML Anomaly",
                    "Logic": "robust feature z-score anomaly score above threshold",
                    "Threshold": "0.72",
                    "Severity": "Medium/High",
                },
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )


def main() -> None:
    require_login()
    is_public_demo = public_demo_mode_enabled(safe_secrets())
    st.title("Vehicular IDS Dashboard")
    st.caption(
        "Production-style rule + anomaly IDS demo for CAN bus logs, with DBC decoding, "
        "stream replay, SQLite persistence, benchmark scoring, and incident triage."
    )

    (
        uploaded_file,
        rule_engine,
        flood_threshold,
        persist_results,
        regenerate_sample,
        reset_session,
    ) = render_sidebar(is_public_demo)

    if regenerate_sample:
        save_current_demo_dataset(DEMO_DATASET_PATH)
        st.session_state["demo_dataset_path"] = str(DEMO_DATASET_PATH)
        rebuild_replay_reader()
        reset_demo_session()
        st.sidebar.success("Current-time demo dataset regenerated.")

    if reset_session:
        reset_demo_session()
        st.sidebar.success("Demo session reset.")

    try:
        result = run_current_pipeline(uploaded_file, rule_engine, persist_results)
    except Exception as error:
        st.error(f"Unable to process the selected dataset: {error}")
        st.stop()

    if uploaded_file is None:
        st.info(f"Using current-time demo dataset: {get_demo_dataset_path().name}")
    else:
        st.success(f"Using uploaded dataset: {uploaded_file.name}")

    tabs = st.tabs(
        [
            "SOC Overview",
            "Incident Queue",
            "Packet Explorer",
            "Live Stream",
            "SQLite History",
            "Rules & Policy",
        ]
    )

    with tabs[0]:
        render_overview_tab(result, flood_threshold)
    with tabs[1]:
        render_alerts_tab(result)
    with tabs[2]:
        render_packets_tab(result)
    with tabs[3]:
        render_stream_tab(rule_engine, persist_results)
    with tabs[4]:
        render_storage_tab(is_public_demo)
    with tabs[5]:
        render_rules_tab(rule_engine)


if __name__ == "__main__":
    main()
