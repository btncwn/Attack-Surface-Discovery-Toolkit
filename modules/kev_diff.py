"""
KEV Diff Module

Compares previous and current CISA KEV intelligence results.
"""


def compare_kev(previous_report: dict, current_report: dict) -> dict:
    previous_report = previous_report or {}
    current_report = current_report or {}

    previous_kevs = {
        item.get("cveID")
        for item in previous_report.get("kev_intelligence", [])
        if isinstance(item, dict) and item.get("cveID")
    }

    current_kevs = {
        item.get("cveID")
        for item in current_report.get("kev_intelligence", [])
        if isinstance(item, dict) and item.get("cveID")
    }

    return {
        "new_kevs": sorted(current_kevs - previous_kevs),
        "resolved_kevs": sorted(previous_kevs - current_kevs),
    }
