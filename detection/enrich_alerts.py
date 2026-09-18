"""
enrich_alerts.py

Purpose: Add analyst-friendly context to existing alerts - human-readable
service names, campaign duration, attempt rate, and a plain-language
description. Does not change detection logic or severity - purely adds
context on top of what already exists in the 'alerts' table.
"""

import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")
ALERTS_TABLE = "alerts"

# Well-known port -> service name mapping (small, targeted - just what
# this project's dataset actually uses; a real system would use a
# fuller reference list)
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
}


def enrich_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df["first_seen"] = pd.to_datetime(df["first_seen"])
    df["last_seen"] = pd.to_datetime(df["last_seen"])

    df["service"] = df["dest_port"].map(PORT_SERVICE_MAP).fillna("Unknown")

    df["duration_minutes"] = (
        (df["last_seen"] - df["first_seen"]).dt.total_seconds() / 60
    ).round(2)

    # Guard against divide-by-zero for any alert with ~0 duration
    df["attempts_per_minute"] = df.apply(
        lambda row: round(row["flagged_flow_count"] / row["duration_minutes"], 1)
        if row["duration_minutes"] > 0 else row["flagged_flow_count"],
        axis=1
    )

    df["description"] = df.apply(
        lambda row: (
            f"Source {row['source_ip']} made {row['flagged_flow_count']} "
            f"connection attempts to {row['service']} (port {row['dest_port']}) "
            f"over {row['duration_minutes']} minutes "
            f"(~{row['attempts_per_minute']} attempts/min). "
            f"Severity: {row['severity']}."
        ),
        axis=1
    )

    return df


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading existing alerts...")
    df = pd.read_sql(f"SELECT * FROM {ALERTS_TABLE}", engine)
    print(f"Loaded {len(df)} alert(s).")

    print("Enriching...")
    enriched = enrich_alerts(df)

    enriched.to_sql(ALERTS_TABLE, engine, if_exists="replace", index=False)
    print(f"Saved enriched alerts back to '{ALERTS_TABLE}'.\n")

    print("Enriched alert descriptions:\n")
    for _, row in enriched.iterrows():
        print(f"[{row['severity']}] {row['description']}")


if __name__ == "__main__":
    main()
