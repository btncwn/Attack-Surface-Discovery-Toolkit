"""
Asset Diff Module

Compares previous and current full report JSON data to identify exposure changes.
"""


def _to_hostname_set(items) -> set:
    results = set()

    if not items:
        return results

    for item in items:
        if isinstance(item, dict) and item.get("subdomain"):
            results.add(item["subdomain"])
        elif isinstance(item, str):
            results.add(item)

    return results


def compare_asset_inventory(previous_report: dict, current_report: dict) -> dict:
    previous_report = previous_report or {}
    current_report = current_report or {}

    previous_subdomains = _to_hostname_set(previous_report.get("subdomains", []))
    current_subdomains = _to_hostname_set(current_report.get("subdomains", []))

    previous_ct = _to_hostname_set(previous_report.get("certificate_transparency_subdomains", []))
    current_ct = _to_hostname_set(current_report.get("certificate_transparency_subdomains", []))

    previous_ports = set(previous_report.get("open_ports", []) or [])
    current_ports = set(current_report.get("open_ports", []) or [])

    return {
        "new_subdomains": sorted(current_subdomains - previous_subdomains),
        "removed_subdomains": sorted(previous_subdomains - current_subdomains),
        "new_ct_assets": sorted(current_ct - previous_ct),
        "removed_ct_assets": sorted(previous_ct - current_ct),
        "new_ports": sorted(current_ports - previous_ports),
        "closed_ports": sorted(previous_ports - current_ports),
    }
