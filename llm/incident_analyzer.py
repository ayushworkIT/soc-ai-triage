"""
incident_analyzer.py

Purpose: Send a single incident's structured data to the Anthropic API,
enforce a strict JSON response schema, validate the response, and
return it as a Python dict. This is the ONLY place in the project
that talks to the LLM - detection, correlation, and incident-building
remain fully deterministic and LLM-free (see Phases 3-4).
"""

import os
import json
import time
from pathlib import Path
from dotenv import load_dotenv
import anthropic

load_dotenv()

MODEL_NAME = "claude-haiku-4-5-20251001"
MAX_RETRIES = 2

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant. You will be given
structured data about a security incident that has already been detected and
correlated by an automated pipeline. Your job is to analyze it and provide
your assessment.

CRITICAL RULES:
1. Respond with ONLY a valid JSON object - no markdown code fences, no preamble,
   no explanation outside the JSON.
2. The JSON must match this exact schema:
{
  "narrative_summary": "2-3 sentence plain-English explanation of what likely happened",
  "confidence": "High | Medium | Low",
  "mitre_attack_techniques": [
    {
      "technique_id": "Txxxx",
      "technique_name": "string",
      "justification": "one sentence on why this technique applies"
    }
  ],
  "recommended_actions": ["short specific action", "..."],
  "false_positive_likelihood": "Low | Medium | High",
  "severity_agreement": {
    "agrees_with_rule_based_severity": true,
    "llm_suggested_severity": "Low | Medium | High | Critical",
    "explanation": "one sentence on why it agrees or disagrees"
  },
  "reasoning_notes": "1-2 sentences on any caveats, uncertainty, or alternative explanations"
}
3. Base your analysis ONLY on the data provided. Do not invent details not
   present in the incident data.
4. Be honest about uncertainty - if the evidence is ambiguous, say so in
   confidence and reasoning_notes rather than presenting a guess as fact."""


def build_incident_prompt(incident):
    return "INCIDENT DATA:\nTitle: " + incident["title"] + "\nSeverity (rule-based): " + incident["severity"] + "\nAlert count: " + str(incident["alert_count"]) + "\nSource IP(s): " + incident["source_ips"] + "\nTarget service(s): " + incident["services"] + "\nTarget port(s): " + incident["dest_ports"] + "\nTime window: " + str(incident["incident_start"]) + " to " + str(incident["incident_end"]) + " (" + str(incident["duration_minutes"]) + " minutes)\nTotal flagged network flows: " + str(incident["total_flagged_flows"])


def analyze_incident(incident, client=None):
    if client is None:
        client = anthropic.Anthropic()

    user_prompt = build_incident_prompt(incident)

    last_error = None
    raw_text = ""
    for attempt in range(1, MAX_RETRIES + 2):
        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw_text = response.content[0].text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        try:
            parsed = json.loads(raw_text)
            return parsed
        except json.JSONDecodeError as e:
            last_error = e
            print("  Attempt " + str(attempt) + ": LLM response was not valid JSON, retrying...")
            time.sleep(1)

    error_msg = "LLM did not return valid JSON after " + str(MAX_RETRIES + 1) + " attempts. Last error: " + str(last_error) + ". Raw response: " + raw_text[:200]
    raise ValueError(error_msg)


if __name__ == "__main__":
    test_incident = {
        "title": "Coordinated FTP brute-force activity (3 sources)",
        "severity": "Critical",
        "alert_count": 3,
        "source_ips": "10.0.0.50,10.0.0.51,10.0.0.52",
        "services": "FTP",
        "dest_ports": "21",
        "incident_start": "2017-07-04 08:12:21",
        "incident_end": "2017-07-04 09:10:36",
        "duration_minutes": 58.25,
        "total_flagged_flows": 7889,
    }

    print("Sending test incident to LLM...")
    result = analyze_incident(test_incident)
    print(json.dumps(result, indent=2))
