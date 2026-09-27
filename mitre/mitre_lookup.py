"""
mitre_lookup.py

Purpose: Load the full MITRE ATT&CK Enterprise dataset once, extract
a clean technique_id -> {name, description, parent_name, combined_name}
lookup table, and provide a validation function to check whether an
LLM-claimed technique ID and name actually match official MITRE data.

Checks the claimed name against BOTH the bare official name (e.g. "SSH")
AND the common "Parent: Sub-technique" display convention (e.g.
"Remote Services: SSH") used by tools like ATT&CK Navigator - so a
correct answer in either format is accepted, and only genuine
mismatches are flagged.
"""

import json
from pathlib import Path

MITRE_DATA_PATH = Path("mitre/enterprise-attack.json")

_technique_cache = None


def load_techniques() -> dict:
    global _technique_cache
    if _technique_cache is not None:
        return _technique_cache

    with open(MITRE_DATA_PATH) as f:
        data = json.load(f)

    raw_techniques = {}
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if technique_id is None:
            continue

        raw_techniques[technique_id] = {
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:300],
        }

    # Second pass: build combined "Parent: Sub-technique" names for
    # any sub-technique (ID containing a dot, e.g. T1021.004)
    techniques = {}
    for tech_id, info in raw_techniques.items():
        if "." in tech_id:
            parent_id = tech_id.split(".")[0]
            parent_name = raw_techniques.get(parent_id, {}).get("name", "")
            combined_name = f"{parent_name}: {info['name']}" if parent_name else info["name"]
        else:
            combined_name = info["name"]

        techniques[tech_id] = {
            "name": info["name"],
            "combined_name": combined_name,
            "description": info["description"],
        }

    _technique_cache = techniques
    return techniques


def validate_technique(technique_id: str, claimed_name: str) -> dict:
    """
    Check whether a technique_id exists in MITRE ATT&CK, and whether the
    claimed name matches EITHER the bare official name or the
    'Parent: Sub-technique' display convention.
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
    combined_name = techniques[technique_id]["combined_name"]
    claimed_normalized = claimed_name.strip().lower()

    name_matches = (
        claimed_normalized == official_name.strip().lower()
        or claimed_normalized == combined_name.strip().lower()
    )

    return {
        "valid_id": True,
        "name_matches": name_matches,
        "official_name": official_name,
        "note": "OK" if name_matches else f"Name mismatch: LLM said '{claimed_name}', official name is '{official_name}' (or '{combined_name}').",
    }


if __name__ == "__main__":
    print("Loading MITRE ATT&CK techniques...")
    techniques = load_techniques()
    print(f"Loaded {len(techniques)} techniques.\n")

    test_cases = [
        ("T1110", "Brute Force"),
        ("T1021.004", "Remote Services: SSH"),
        ("T1021.004", "Remote System Discovery"),
        ("T1595.003", "Active Scanning: Brute Force"),
        ("T9999", "Fake Technique"),
    ]

    for tech_id, claimed_name in test_cases:
        result = validate_technique(tech_id, claimed_name)
        print(f"{tech_id} ('{claimed_name}'):")
        print(f"  Valid ID: {result['valid_id']}")
        print(f"  Name matches: {result['name_matches']}")
        print(f"  Official name: {result['official_name']}")
        print(f"  Note: {result['note']}")
        print()
