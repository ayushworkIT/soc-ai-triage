"""
mitre_lookup.py

Purpose: Load the full MITRE ATT&CK Enterprise dataset once, extract
a clean technique_id -> {name, description} lookup table, and provide
a validation function to check whether an LLM-claimed technique ID
and name actually match the official MITRE reference data.
"""

import json
from pathlib import Path

MITRE_DATA_PATH = Path("mitre/enterprise-attack.json")

_technique_cache = None


def load_techniques() -> dict:
    """Load and cache a technique_id -> {name, description} lookup table."""
    global _technique_cache
    if _technique_cache is not None:
        return _technique_cache

    with open(MITRE_DATA_PATH) as f:
        data = json.load(f)

    techniques = {}
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Technique ID lives inside external_references, marked as mitre-attack source
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if technique_id is None:
            continue

        techniques[technique_id] = {
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:300],  # trimmed
        }

    _technique_cache = techniques
    return techniques


def validate_technique(technique_id: str, claimed_name: str) -> dict:
    """
    Check whether a technique_id exists in MITRE ATT&CK, and whether the
    claimed name matches the official name.

    Returns a dict describing validation result - used to catch LLM
    hallucinations like inventing a technique_id or mismatching a name.
    """
    techniques = load_techniques()

    if technique_id not in techniques:
        return {
            "valid_id": False,
            "name_matches": False,
            "official_name": None,
            "note": f"Technique ID '{technique_id}' does not exist in MITRE ATT&CK.",
        }

    official_name = techniques[technique_id]["name"]
    name_matches = claimed_name.strip().lower() == official_name.strip().lower()

    return {
        "valid_id": True,
        "name_matches": name_matches,
        "official_name": official_name,
        "note": "OK" if name_matches else f"Name mismatch: LLM said '{claimed_name}', official name is '{official_name}'.",
    }


if __name__ == "__main__":
    print("Loading MITRE ATT&CK techniques...")
    techniques = load_techniques()
    print(f"Loaded {len(techniques)} techniques.\n")

    # Test against the two techniques the LLM returned in Step 16
    test_cases = [
        ("T1110", "Brute Force"),
        ("T1021.001", "Remote Services: SSH"),
        ("T9999", "Fake Technique"),  # deliberately invalid, to test the failure path
    ]

    for tech_id, claimed_name in test_cases:
        result = validate_technique(tech_id, claimed_name)
        print(f"{tech_id} ('{claimed_name}'):")
        print(f"  Valid ID: {result['valid_id']}")
        print(f"  Name matches: {result['name_matches']}")
        print(f"  Official name: {result['official_name']}")
        print(f"  Note: {result['note']}")
        print()
