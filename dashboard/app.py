"""
app.py

Purpose: Streamlit dashboard presenting the full pipeline's output -
incidents, their rule-based data, LLM analysis, and MITRE ATT&CK
validation - in a single, demo-able web interface.
"""

import json
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")

st.set_page_config(page_title="SOC AI Triage Dashboard", layout="wide")


@st.cache_resource
def get_engine():
    return create_engine(f"sqlite:///{DB_PATH}")


def load_data():
    engine = get_engine()
    incidents = pd.read_sql("SELECT * FROM incidents", engine)
    analysis = pd.read_sql("SELECT * FROM llm_analysis", engine)
    merged = incidents.merge(analysis, on="incident_id", suffixes=("", "_llm"))
    return merged


def severity_color(severity: str) -> str:
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
    }.get(severity, "⚪")


def main():
    st.title("🛡️ AI-Powered SOC Alert Triage Dashboard")
    st.caption("Detection -> Correlation -> Incident -> LLM Analysis -> MITRE ATT&CK Validation")

    data = load_data()

    # --- Top-level metrics ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Incidents", len(data))
    col2.metric("LLM/Rule Severity Agreement",
                f"{data['llm_agrees_with_severity'].sum()} / {len(data)}")
    col3.metric("Techniques w/ Hallucination",
                f"{data['any_technique_hallucinated'].sum()} / {len(data)}")
    col4.metric("Total Flagged Flows", int(data['total_flagged_flows'].sum()))

    st.divider()

    # --- One expandable section per incident ---
    for _, row in data.iterrows():
        header = f"{severity_color(row['severity'])} {row['title']}  —  Rule severity: {row['severity']}"
        with st.expander(header, expanded=True):
            left, right = st.columns([1, 1])

            with left:
                st.subheader("📊 Rule-Based Detection")
                st.write(f"**Source IPs:** {row['source_ips']}")
                st.write(f"**Service(s):** {row['services']}")
                st.write(f"**Time window:** {row['incident_start']} → {row['incident_end']}")
                st.write(f"**Duration:** {row['duration_minutes']} minutes")
                st.write(f"**Alert count:** {row['alert_count']}")
                st.write(f"**Total flagged flows:** {row['total_flagged_flows']}")

            with right:
                st.subheader("🤖 LLM Analysis")
                st.write(f"**Confidence:** {row['llm_confidence']}")
                st.write(f"**False positive likelihood:** {row['false_positive_likelihood']}")

                agree_icon = "✅" if row['llm_agrees_with_severity'] else "⚠️"
                st.write(f"**Severity agreement:** {agree_icon} "
                         f"(LLM suggests: {row['llm_suggested_severity']})")
                if not row['llm_agrees_with_severity']:
                    st.info(row['severity_explanation'])

            st.write("**Narrative summary:**")
            st.write(row['narrative_summary'])

            st.write("**Recommended actions:**")
            actions = json.loads(row['recommended_actions'])
            for action in actions:
                st.write(f"- {action}")

            st.write("**MITRE ATT&CK Techniques:**")
            techniques = json.loads(row['mitre_techniques_validated'])
            for t in techniques:
                status_icon = "✅" if (t['valid_id'] and t['name_matches']) else "❌"
                st.write(f"{status_icon} `{t['technique_id']}` — {t['claimed_name']}")
                if not (t['valid_id'] and t['name_matches']):
                    st.caption(f"  ⚠️ {t['validation_note']}")

            st.write("**Reasoning notes:**")
            st.caption(row['reasoning_notes'])


if __name__ == "__main__":
    main()
