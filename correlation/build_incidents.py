"""
build_incidents.py

Purpose: Materialize each incident_id group (from correlate_alerts.py)
into a proper Incident record: combined timeline, aggregated
indicators (all source IPs, ports, services involved), overall
severity (highest among constituent alerts), and alert count.
Stored in a new 'incidents' table - the object Phase 5's LLM layer
will consume.
"""

import uuid
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")
ALERTS_TABLE = "alerts"
INCIDENTS_TABLE = "incidents"

# Severity ranking - higher number = more severe. Used to pick the
# "worst" severity among an incident's alerts.
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def build_incident_record(incident_id: str, alerts_group: pd.DataFrame) -> dict:
    """Aggregate one incident_id's alerts into a single Incident record."""

    overall_severity = max(
        alerts_group["severity"], key=lambda s: SEVERITY_RANK.get(s, 0)
    )

    source_ips = sorted(alerts_group["source_ip"].unique().tolist())
    services = sorted(alerts_group["service"].unique().tolist())
    dest_ports = sorted(alerts_group["dest_port"].unique().tolist())

    incident_start = alerts_group["first_seen"].min()
    incident_end = alerts_group["last_seen"].max()
    duration_minutes = round((incident_end - incident_start).total_seconds() / 60, 2)

    total_flagged_flows = alerts_group["flagged_flow_count"].sum()

    title = (
        f"{'Coordinated' if len(alerts_group) > 1 else 'Isolated'} "
        f"{'/'.join(services)} brute-force activity "
        f"({len(source_ips)} source{'s' if len(source_ips) != 1 else ''})"
    )

    return {
        "incident_id": incident_id,
        "title": title,
        "severity": overall_severity,
        "alert_count": len(alerts_group),
        "source_ips": ",".join(source_ips),
        "services": ",".join(services),
        "dest_ports": ",".join(str(p) for p in dest_ports),
        "incident_start": incident_start,
        "incident_end": incident_end,
        "duration_minutes": duration_minutes,
        "total_flagged_flows": int(total_flagged_flows),
    }


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading correlated alerts...")
    alerts = pd.read_sql(
        f"SELECT * FROM {ALERTS_TABLE}", engine,
        parse_dates=["first_seen", "last_seen"]
    )
    print(f"Loaded {len(alerts)} alert(s) across {alerts['incident_id'].nunique()} incident(s).")

    incidents = []
    for incident_id, group in alerts.groupby("incident_id"):
        incidents.append(build_incident_record(incident_id, group))

    incidents_df = pd.DataFrame(incidents)
    incidents_df = incidents_df.sort_values("incident_start").reset_index(drop=True)

    incidents_df.to_sql(INCIDENTS_TABLE, engine, if_exists="replace", index=False)
    print(f"Saved {len(incidents_df)} incident(s) to '{INCIDENTS_TABLE}'.\n")

    print("Incident summary:\n")
    for _, row in incidents_df.iterrows():
        print(f"[{row['severity']}] {row['title']}")
        print(f"    Sources: {row['source_ips']}")
        print(f"    Window: {row['incident_start']} to {row['incident_end']} "
              f"({row['duration_minutes']} min)")
        print(f"    Alerts: {row['alert_count']}  |  Total flagged flows: {row['total_flagged_flows']}")
        print()


if __name__ == "__main__":
    main()
