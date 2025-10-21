# dashboard.py
# Anomaly Guard – Streamlit Dashboard (auto-refresh + timeline)
# -------------------------------------------------------------
# pip install streamlit boto3 pandas matplotlib python-dateutil streamlit-autorefresh

import os, json
from datetime import datetime, timezone
from dateutil import parser as dtparse
import boto3
import pandas as pd
import streamlit as st

# ---------- CONFIG ----------
AWS_REGION   = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET    = os.getenv("ANOGUARD_S3_BUCKET", "lstm-model-output")
S3_PREFIX    = os.getenv("ANOGUARD_S3_PREFIX", "athena-ready/")
MAX_LIST     = 50

# ---------- HELPERS ----------
def s3_client():
    return boto3.client("s3", region_name=AWS_REGION)

def list_recent_json_objects():
    cli = s3_client()
    objs = []
    kwargs = dict(Bucket=S3_BUCKET, Prefix=S3_PREFIX)
    while True:
        resp = cli.list_objects_v2(**kwargs)
        for o in resp.get("Contents", []):
            if o["Key"].endswith(".json"):
                objs.append(o)
        if resp.get("IsTruncated"):
            kwargs["ContinuationToken"] = resp["NextContinuationToken"]
        else:
            break
    objs.sort(key=lambda x: x["LastModified"], reverse=True)
    return objs[:MAX_LIST]

def read_json_from_s3(key):
    cli = s3_client()
    obj = cli.get_object(Bucket=S3_BUCKET, Key=key)
    raw = obj["Body"].read().decode("utf-8").strip()
    try:
        if "\n" in raw:
            for line in raw.splitlines():
                if line.strip():
                    return json.loads(line)
        return json.loads(raw)
    except Exception:
        return json.loads("".join(raw.split()))

def fmt_dt(s):
    try:
        return dtparse.parse(s).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception:
        return s

# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="Anomaly Guard Dashboard", layout="wide")
st.title("Anomaly Guard – AI Threat Analysis Dashboard")

# AUTO REFRESH CONTROL
from streamlit_autorefresh import st_autorefresh
refresh_interval = st.sidebar.slider("Auto-refresh interval (seconds)", 10, 120, 30)
st_autorefresh(interval=refresh_interval * 1000, key="data_refresh")

with st.sidebar:
    st.header("Data Source")
    st.caption("Reads the latest AI analysis JSON written by your Lambda.")
    st.text(f"S3: s3://{S3_BUCKET}/{S3_PREFIX}")
    st.divider()
    auto = st.checkbox("Auto-select newest file", value=True)

    s3_ok = True
    try:
        recent = list_recent_json_objects()
    except Exception as e:
        s3_ok = False
        recent = []
        st.error("Could not list S3 objects. Upload a local file instead.")
        st.exception(e)

    selected_key = None
    if s3_ok and recent:
        keys = [o["Key"] for o in recent]
        labels = [f"{os.path.basename(k)} · {o['LastModified'].strftime('%Y-%m-%d %H:%M:%S')}" for k, o in zip(keys, recent)]
        if auto:
            selected_key = keys[0]
            st.success(f"Newest file selected:\n{os.path.basename(selected_key)}")
        else:
            idx = st.selectbox("Choose a file", options=list(range(len(keys))), format_func=lambda i: labels[i])
            selected_key = keys[idx]
    else:
        uploaded = st.file_uploader("Upload a JSON report", type=["json"])
        if uploaded:
            selected_key = "__LOCAL_UPLOAD__"
            local_bytes = uploaded.read()

# ---------- Load JSON ----------
data = None
try:
    if selected_key == "__LOCAL_UPLOAD__":
        data = json.loads(local_bytes.decode("utf-8"))
    elif selected_key:
        data = read_json_from_s3(selected_key)
except Exception as e:
    st.error(f"Error loading data: {e}")
    st.stop()

if not data:
    st.info("No data loaded.")
    st.stop()

# ---------- Extract dynamic sections ----------
summary = data.get("summary", {})
ta = data.get("threat_analysis", {})
ctx = ta.get("context_analysis", {})
breakdown = ta.get("malicious_events_breakdown", {})

# Determine dynamic labels
threat_type = ta.get("threat_type", "Detected")
risk_level = ta.get("risk_level", "UNKNOWN")
confidence = float(ta.get("confidence", 0) or 0)
threat_label = threat_type.replace("_", " ").title()

# ---------- Header & KPIs ----------
st.markdown(f"**Threat Type:** {threat_label}  •  **Risk Level:** {risk_level}  •  **Confidence:** {confidence:.3f}")
time_range = summary.get("time_range", {})
st.caption(f"Time Range: {fmt_dt(time_range.get('start_time', ''))} → {fmt_dt(time_range.get('end_time', ''))}")

total_events = int(summary.get("total_events", 0) or 0)
total_mal = int(breakdown.get("total_malicious", 0) or 0)
mal_percent = round((total_mal / total_events * 100), 2) if total_events else 0.0

# Detect main breakdown key dynamically
priv_key = next(iter(breakdown.keys()), "Detected Events")
priv_events = breakdown.get(priv_key, [])
if isinstance(priv_events, dict):
    priv_events = priv_events.get(next(iter(priv_events.keys())), [])

detected_users = len(set([e.get("Username", "") for e in priv_events if e.get("Username")]))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", f"{total_events:,}")
c2.metric("Malicious Events", f"{total_mal:,}", delta=f"{mal_percent}%")
c3.metric("Model Confidence", f"{confidence*100:.2f}%")
c4.metric("Detected Users", f"{detected_users}")

st.divider()
# ---------- Dynamic Events Table ----------
section_name = f"{threat_label} Events"
st.subheader(section_name)

df_mal = pd.DataFrame(priv_events)
if not df_mal.empty:
    if "EventTime" in df_mal.columns:
        df_mal["EventTimeParsed"] = pd.to_datetime(df_mal["EventTime"], errors="coerce")
        df_mal = df_mal.sort_values("EventTimeParsed", ascending=False)

    show_cols = [c for c in ["EventTime", "EventName", "Username", "EventId", "ErrorCode"] if c in df_mal.columns]
    st.dataframe(df_mal[show_cols], use_container_width=True, height=360)

    # ---------- Timeline Chart ----------
    if "EventTimeParsed" in df_mal.columns:
        st.subheader("Event Timeline")
        freq = "1H" if len(df_mal) > 30 else "5T"
        timeline = df_mal.groupby(pd.Grouper(key="EventTimeParsed", freq=freq)).size()
        if not timeline.empty:
            st.line_chart(timeline)
        else:
            st.info("No valid timestamps found for timeline.")
else:
    st.info(f"No {threat_label.lower()} events found in this report.")

st.divider()

# ---------- Events by Source ----------
events_by_source = summary.get("events_by_source", {})
if events_by_source:
    st.subheader("Events by Source")
    df_src = pd.DataFrame(
        [{"Source": k.replace("_", "."), "Events": int(v or 0)} for k, v in events_by_source.items()]
    ).sort_values("Events", ascending=False)
    st.bar_chart(df_src.set_index("Source"))

st.divider()

# ---------- Context Analysis ----------
if ctx:
    st.subheader("Context Analysis")
    trust = float(ctx.get("trust_score", 0) or 0)
    risk = float(ctx.get("risk_score", 0) or 0)
    df_scores = pd.DataFrame({"Score": [trust, risk]}, index=["Trust Score", "Risk Score"])
    st.bar_chart(df_scores)

    col1, col2 = st.columns(2)
    col1.write("#### Trust Signals")
    for s in ctx.get("trust_signals", []):
        col1.write(f"- {s}")
    col2.write("#### Risk Signals")
    for s in ctx.get("risk_signals", []):
        col2.write(f"- {s}")


st.divider()

# ---------- Model Metadata ----------
st.subheader("Model Explanation & Metadata")
st.write(f"**Model Type:** {data.get('model_type', '—')}")
st.write(f"**Prediction Method:** {data.get('prediction_method', '—')}")
for f in ta.get("risk_factors", []):
    st.write(f"- {f}")

source_file = os.path.basename(selected_key) if selected_key != "__LOCAL_UPLOAD__" else "Local upload"
st.caption(f"Source file: {source_file}")
