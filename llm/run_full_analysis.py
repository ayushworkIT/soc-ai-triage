"""
run_full_analysis.py

Purpose: Run the complete Phase 5 pipeline against all real incidents
in the database - LLM analysis (Step 16) + MITRE ATT&CK validation
(Step 17) - and store the combined results in an 'llm_analysis' table
for use in the dashboard (Phase 6) and evaluation.
"""

import sys
import json
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

sys.path.insert(0, ".")
from llm.incident_analyzer import analyze_incident
from mitre.mitre_lookup import validate_technique

DB_PATH = Path("database/soc_ai_triage.db")
ANALYSIS_TABLE = "llm_analysis"


def validate_all_techniques(techniques: list) -> list:
    """Run MITRE validation on every technique the LLM claimed."""
    validated = []
    for t in techniques:
        result = validate_technique(t["technique_id"], t["technique_name"])
        validated.append({
            "technique_id": t["technique_id"],
            "claimed_name": t["technique_name"],
            "justification": t["justification"],
            "valid_id": result["valid_id"],
            "name_matches": result["name_matches"],
            "official_name": result["official_name"],
            "validation_note": result["note"],
        })
    return validated


def main():
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print("Loading incidents...")
    incidents = pd.read_sql("SELECT * FROM incidents", engine)
    print(f"Loaded {len(incidents)} incident(s).\n")

    results = []

    for _, incident in incidents.iterrows():
        print(f"Analyzing: {incident['title']} [{incident['severity']}]...")

        incident_dict = incident.to_dict()
        analysis = analyze_incident(incident_dict)

        validated_techniques = validate_all_techniques(analysis["mitre_attack_techniques"])
        any_hallucinated = any(
            (not v["valid_id"]) or (not v["name_matches"]) for v in validated_techniques
        )

        results.append({
            "incident_id": incident["incident_id"],
            "incident_title": incident["title"],
            "rule_based_severity": incident["severity"],
            "narrative_summary": analysis["narrative_summary"],
            "llm_confidence": analysis["confidence"],
            "false_positive_likelihood": analysis["false_positive_likelihood"],
            "llm_agrees_with_severity": analysis["severity_agreement"]["agrees_with_rule_based_severity"],
            "llm_suggested_severity": analysis["severity_agreement"]["llm_suggested_severity"],
            "severity_explanation": analysis["severity_agreement"]["explanation"],
            "recommended_actions": json.dumps(analysis["recommended_actions"]),
            "mitre_techniques_raw": json.dumps(analysis["mitre_attack_techniques"]),
            "mitre_techniques_validated": json.dumps(validated_techniques),
            "any_technique_hallucinated": any_hallucinated,
            "reasoning_notes": analysis["reasoning_notes"],
        })

        print(f"  Confidence: {analysis['confidence']} | FP likelihood: {analysis['false_positive_likelihood']}")
        print(f"  Severity agreement: {analysis['severity_agreement']['agrees_with_rule_based_severity']}")
        print(f"  Techniques flagged as hallucinated: {any_hallucinated}\n")

    results_df = pd.DataFrame(results)
    results_df.to_sql(ANALYSIS_TABLE, engine, if_exists="replace", index=False)
    print(f"Saved {len(results_df)} analysis result(s) to '{ANALYSIS_TABLE}'.")

    print("\n=== SUMMARY ===")
    print(f"Total incidents analyzed: {len(results_df)}")
    print(f"LLM agreed with rule-based severity: {results_df['llm_agrees_with_severity'].sum()} / {len(results_df)}")
    print(f"Incidents with a hallucinated technique: {results_df['any_technique_hallucinated'].sum()} / {len(results_df)}")


if __name__ == "__main__":
    main()
