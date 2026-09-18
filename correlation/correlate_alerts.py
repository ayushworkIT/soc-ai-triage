"""
correlate_alerts.py

Purpose: Group alerts into incidents based on TIME OVERLAP - alerts
whose [first_seen, last_seen] windows overlap (regardless of source
IP) are considered part of the same coordinated campaign/incident.
Alerts with no time overlap with any other alert become their own
standalone incident.

This deliberately correlates by TIME, not by source_ip - the whole
point is to catch multiple different sources acting together in the
same window (a distributed/coordinated pattern), which grouping by
source_ip alone would miss entirely.
"""

import uuid
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")
ALERTS_TABLE = "alerts"


def intervals_overlap(start1, end1, start2, end2) -> bool:
    """Two time intervals overlap if one starts before the other ends,
    in both directions."""
    return start1 <= end2 and start2 <= end1


def correlate(alerts: pd.DataFrame) -> pd.DataFrame:
    """Assign an incident_id to each alert based on time-window overlap.
    Uses a simple union-find style grouping: repeatedly merge any two
    alerts whose windows overlap until no more merges are possible.
    """
    alerts = alerts.sort_values("first_seen").reset_index(drop=True)
    n = len(alerts)

    # Start: each alert is its own group
    group_id = list(range(n))

    def find(i):
        while group_id[i] != i:
            i = group_id[i]
        return i

    def union(i, j):
        gi, gj = find(i), find(j)
        if gi != gj:
            group_id[gi] = gj

    # Compare every pair of alerts - fine at this scale (7 alerts = 21 comparisons).
    # A production system with thousands of alerts would use a more efficient
    # sweep-line or indexed approach instead of pairwise comparison.
    for i in range(n):
        for j in range(i + 1, n):
            if intervals_overlap(
                alerts.loc[i, "first_seen"], alerts.loc[i, "last_seen"],
                alerts.loc[j, "first_seen"], alerts.loc[j, "last_seen"],
            ):
                union(i, j)

    alerts["_group"] = [find(i) for i in range(n)]

    # Convert internal group numbers into stable incident IDs
    group_to_incident = {}
    for g in alerts["_group"].unique():
        group_to_incident[g] = str(uuid.uuid4())
    alerts["incident_id"] = alerts["_group"].map(group_to_incident)

    return alerts.drop(columns=["_group"])


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading alerts...")
    alerts = pd.read_sql(f"SELECT * FROM {ALERTS_TABLE}", engine, parse_dates=["first_seen", "last_seen"])
    print(f"Loaded {len(alerts)} alert(s).")

    print("Correlating by time overlap...")
    correlated = correlate(alerts)

    incident_counts = correlated.groupby("incident_id").size()
    print(f"Grouped {len(alerts)} alerts into {len(incident_counts)} incident(s).\n")

    for incident_id, group in correlated.groupby("incident_id"):
        print(f"Incident {incident_id[:8]}... ({len(group)} alert(s)):")
        for _, row in group.iterrows():
            print(f"    - {row['source_ip']} -> {row['service']} (port {row['dest_port']}), "
                  f"severity={row['severity']}, {row['first_seen']} to {row['last_seen']}")
        print()

    correlated.to_sql(ALERTS_TABLE, engine, if_exists="replace", index=False)
    print(f"Saved incident_id assignments back to '{ALERTS_TABLE}'.")


if __name__ == "__main__":
    main()
