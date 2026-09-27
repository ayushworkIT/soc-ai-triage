"""
run_evaluation.py

Purpose: Recompute every evaluation metric for the project from stored
data - detection accuracy, alert reduction, correlation correctness,
and LLM performance (severity agreement, hallucination rate) - and
print a single consolidated report. All numbers are derived fresh
from the database, not hard-coded, so results stay reproducible.
"""

import json
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

DB_PATH = Path("database/soc_ai_triage.db")


def detection_metrics(engine):
    """Precision/recall of the brute-force rule against ground-truth labels."""
    flows = pd.read_sql(
        'SELECT is_attack, "Destination Port" as dest_port FROM flows '
        'WHERE "Destination Port" IN (21, 22)', engine
    )
    total_attacks = int(flows["is_attack"].sum())
    total_flows = len(flows)

    alerts = pd.read_sql("SELECT reference_labels, flagged_flow_count FROM alerts", engine)
    true_positive_flows = alerts[alerts["reference_labels"] != "BENIGN"]["flagged_flow_count"].sum()
    false_positive_flows = alerts[alerts["reference_labels"] == "BENIGN"]["flagged_flow_count"].sum()

    precision = true_positive_flows / (true_positive_flows + false_positive_flows)
    recall = true_positive_flows / total_attacks

    return {
        "total_candidate_flows": total_flows,
        "total_actual_attacks": total_attacks,
        "true_positive_flows": int(true_positive_flows),
        "false_positive_flows": int(false_positive_flows),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def alert_reduction_metrics(engine):
    """How much detection flagged flows were reduced by grouping into alerts."""
    alerts = pd.read_sql("SELECT flagged_flow_count FROM alerts", engine)
    total_flagged_flows = int(alerts["flagged_flow_count"].sum())
    total_alerts = len(alerts)
    reduction_pct = round((1 - (total_alerts / total_flagged_flows)) * 100, 2)

    return {
        "total_flagged_flows": total_flagged_flows,
        "total_alerts": total_alerts,
        "alert_reduction_pct": reduction_pct,
    }


def correlation_metrics(engine):
    """How alerts were grouped into incidents."""
    alerts = pd.read_sql("SELECT incident_id FROM alerts", engine)
    incidents = pd.read_sql("SELECT incident_id, alert_count FROM incidents", engine)

    return {
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "alert_to_incident_reduction_pct": round((1 - (len(incidents) / len(alerts))) * 100, 2),
        "incidents_with_multiple_alerts": int((incidents["alert_count"] > 1).sum()),
    }


def llm_metrics(engine):
    """LLM performance: severity agreement and MITRE hallucination rate."""
    analysis = pd.read_sql(
        "SELECT llm_agrees_with_severity, any_technique_hallucinated, "
        "false_positive_likelihood, incident_title FROM llm_analysis", engine
    )

    total = len(analysis)
    agreement_count = int(analysis["llm_agrees_with_severity"].sum())
    hallucination_count = int(analysis["any_technique_hallucinated"].sum())

    return {
        "total_incidents_analyzed": total,
        "severity_agreement_count": agreement_count,
        "severity_agreement_rate": round(agreement_count / total, 4),
        "hallucination_count": hallucination_count,
        "hallucination_rate": round(hallucination_count / total, 4),
        "false_positive_likelihood_by_incident": analysis[
            ["incident_title", "false_positive_likelihood"]
        ].to_dict(orient="records"),
    }


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("=" * 70)
    print("EVALUATION REPORT")
    print("=" * 70)

    print("\n--- 1. Detection Accuracy (Rule-Based) ---")
    det = detection_metrics(engine)
    for k, v in det.items():
        print(f"  {k}: {v}")

    print("\n--- 2. Alert Generation / Reduction ---")
    alert = alert_reduction_metrics(engine)
    for k, v in alert.items():
        print(f"  {k}: {v}")

    print("\n--- 3. Correlation / Incident Grouping ---")
    corr = correlation_metrics(engine)
    for k, v in corr.items():
        print(f"  {k}: {v}")

    print("\n--- 4. LLM Performance ---")
    llm = llm_metrics(engine)
    for k, v in llm.items():
        if k == "false_positive_likelihood_by_incident":
            print(f"  {k}:")
            for item in v:
                print(f"    - {item['incident_title']}: {item['false_positive_likelihood']}")
        else:
            print(f"  {k}: {v}")

    print("\n" + "=" * 70)
    print("END OF REPORT")
    print("=" * 70)

    # Save as JSON too, for use in documentation/README
    report = {
        "detection": det,
        "alert_reduction": alert,
        "correlation": corr,
        "llm_performance": llm,
    }
    output_path = Path("reports/evaluation_report.json")
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nSaved full report to {output_path}")


if __name__ == "__main__":
    main()
