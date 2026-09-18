"""
generate_alerts.py

Purpose: Convert flagged brute-force detections into structured Alert
records, with a unique ID, severity (based on rolling_count quartiles
observed in the data), and key indicators. Persists to an 'alerts'
table so alerts exist as first-class, queryable objects rather than
transient script output.
"""

import sys
import uuid
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

sys.path.insert(0, ".")
from detection.brute_force_rule import load_flows, detect_brute_force

DB_PATH = Path("database/soc_ai_triage.db")
ALERTS_TABLE = "alerts"


def assign_severity(rolling_count: float) -> str:
    """Map a rolling connection count to a severity band, based on
    the real quartile distribution observed in Step 10 analysis."""
    if rolling_count >= 230:
        return "Critical"
    elif rolling_count >= 180:
        return "High"
    elif rolling_count >= 66:
        return "Medium"
    else:
        return "Low"


def build_alerts(flagged: pd.DataFrame) -> pd.DataFrame:
    """Turn flagged detection rows into structured alert records.

    We collapse to ONE alert per (source_ip, dest_port) pair per day,
    representing 'this source triggered brute-force detection' - not
    one alert per individual flagged row (that would be alert-fatigue
    territory, which is exactly what this project is trying to reduce).
    """
    alerts = []

    grouped = flagged.groupby(["source_ip", "dest_port"])

    for (src_ip, port), group in grouped:
        first_flagged_time = group["timestamp"].min()
        last_flagged_time = group["timestamp"].max()
        max_rolling_count = group["rolling_count"].max()
        total_flagged_flows = len(group)

        # Ground-truth label info, kept ONLY as reference metadata -
        # not used by detection logic, only useful for humans reading
        # the alert and for our own evaluation later.
        true_labels = group["Label"].unique().tolist()

        alerts.append({
            "alert_id": str(uuid.uuid4()),
            "rule_name": "volumetric_brute_force",
            "source_ip": src_ip,
            "dest_port": int(port),
            "first_seen": first_flagged_time,
            "last_seen": last_flagged_time,
            "max_rolling_count": max_rolling_count,
            "flagged_flow_count": total_flagged_flows,
            "severity": assign_severity(max_rolling_count),
            "reference_labels": ",".join(true_labels),
        })

    return pd.DataFrame(alerts)


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading flow data and running detection...")
    df = load_flows(engine)
    flagged = detect_brute_force(df)
    print(f"Detection flagged {len(flagged):,} individual flow rows.")

    print("Building structured alerts...")
    alerts_df = build_alerts(flagged)
    print(f"Generated {len(alerts_df)} alert(s).")

    print("\nAlert summary:")
    print(alerts_df[["alert_id", "source_ip", "dest_port", "severity",
                      "max_rolling_count", "flagged_flow_count"]].to_string(index=False))

    alerts_df.to_sql(ALERTS_TABLE, engine, if_exists="replace", index=False)
    print(f"\nSaved {len(alerts_df)} alerts to '{ALERTS_TABLE}' table.")


if __name__ == "__main__":
    main()
