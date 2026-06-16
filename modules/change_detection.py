import json


def _normalise_findings(findings: list) -> set:
    return {
        f"{item.get('severity', '')} - {item.get('finding', '')}"
        for item in findings
    }


def compare_findings(current_findings: list, previous_findings_json: str) -> dict:
    try:
        previous_findings = json.loads(previous_findings_json or "[]")
    except json.JSONDecodeError:
        previous_findings = []

    previous_set = _normalise_findings(previous_findings)
    current_set = _normalise_findings(current_findings)

    new_findings = sorted(list(current_set - previous_set))
    resolved_findings = sorted(list(previous_set - current_set))
    unchanged_findings = sorted(list(current_set & previous_set))

    return {
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "unchanged_count": len(unchanged_findings)
    }
