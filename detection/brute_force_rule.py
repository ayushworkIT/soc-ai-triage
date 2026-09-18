"""
brute_force_rule.py

Purpose: Detect brute-force-style behavior using a volumetric,
time-windowed rule: flag any (source_ip, destination_port) pair
with more than THRESHOLD connection attempts within a rolling
WINDOW_MINUTES window. This mimics how real SIEM brute-force
detection rules work (e.g., "N failed logins in 5 minutes").

Deliberately does NOT use the Label column - detection must stand
on its own. Label is only used later, for evaluation.
"""

import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")
THRESHOLD = 10          # connection attempts
WINDOW_MINUTES = 5      # rolling time window


def load_flows(engine):
    """Load only the columns needed for detection (not the full 79-column table)."""
    query = """
        SELECT timestamp, source_ip, "Destination Port" as dest_port, Label, is_attack
        FROM flows
        WHERE "Destination Port" IN (21, 22)
    """
    df = pd.read_sql(query, engine, parse_dates=["timestamp"])
    return df


def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """
    For each (source_ip, dest_port) group, count connections in a
    rolling WINDOW_MINUTES window. Flag rows where that rolling count
    exceeds THRESHOLD.
    """
    df = df.sort_values("timestamp").reset_index(drop=True)

    flagged_rows = []

    for (src_ip, port), group in df.groupby(["source_ip", "dest_port"]):
        group = group.set_index("timestamp").sort_index()

        # Rolling count of connections in the trailing WINDOW_MINUTES
        rolling_count = group["dest_port"].rolling(f"{WINDOW_MINUTES}min").count()

        group = group.copy()
        group["rolling_count"] = rolling_count.values

        # Flag rows where the rolling count crosses our threshold
        flagged = group[group["rolling_count"] > THRESHOLD]
        flagged_rows.append(flagged.reset_index())

    if flagged_rows:
        result = pd.concat(flagged_rows, ignore_index=True)
    else:
        result = pd.DataFrame()

    return result


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading flow data (ports 21/22 only)...")
    df = load_flows(engine)
    print(f"Loaded {len(df):,} candidate rows.")

    print(f"Running brute-force detection (threshold={THRESHOLD} in {WINDOW_MINUTES}min window)...")
    flagged = detect_brute_force(df)
    print(f"Flagged {len(flagged):,} rows as suspected brute-force activity.")

    if len(flagged) > 0:
        print("\nBreakdown by actual label (for our own sanity-check only):")
        print(flagged["Label"].value_counts())

        print("\nBreakdown by source IP:")
        print(flagged.groupby(["source_ip", "dest_port"]).size())

    return flagged


if __name__ == "__main__":
    main()
