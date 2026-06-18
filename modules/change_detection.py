# modules/change_detection.py
import json
from typing import List, Dict, Union, Set, Tuple


def compare_findings(
    current_findings: List[Dict[str, str]],
    previous_findings_json: Union[str, List[Dict[str, str]]]
) -> Dict[str, List[str]]:
    """
    Detects finding differences between two scans.

    Args:
        current_findings: Mevcut taramadaki findings listesi
        previous_findings_json: Önceki taramadaki findings (JSON string veya liste)

    Returns:
        Dict: {
            "new_findings": List[str],
            "resolved_findings": List[str]
        }
    """
    # Convert JSON string to list
    if isinstance(previous_findings_json, str):
        try:
            previous_findings = json.loads(previous_findings_json)
        except json.JSONDecodeError:
            previous_findings = []
    elif isinstance(previous_findings_json, list):
        previous_findings = previous_findings_json
    else:
        previous_findings = []

    # Convert findings into comparable tuples
    current_set: Set[Tuple[str, str]] = set()
    for f in current_findings:
        finding = f.get('finding', '')
        severity = f.get('severity', '')
        if finding:
            current_set.add((finding, severity))

    previous_set: Set[Tuple[str, str]] = set()
    for f in previous_findings:
        finding = f.get('finding', '')
        severity = f.get('severity', '')
        if finding:
            previous_set.add((finding, severity))

    new_findings = current_set - previous_set
    resolved_findings = previous_set - current_set

    return {
        "new_findings": [
            f"{severity} - {finding}"
            for finding, severity in sorted(new_findings)
        ],
        "resolved_findings": [
            f"{severity} - {finding}"
            for finding, severity in sorted(resolved_findings)
        ]
    }
