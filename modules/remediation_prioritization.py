"""
Remediation Prioritization Engine

Converts technical findings into prioritized remediation actions.
"""


def generate_remediation_plan(report_data: dict) -> dict:
    report_data = report_data or {}

    findings = report_data.get("findings", [])
    kev_intelligence = report_data.get("kev_intelligence", [])
    hidden_asset_intelligence = report_data.get("hidden_asset_intelligence", {})

    p1 = []
    p2 = []
    p3 = []

    if kev_intelligence:
        for item in kev_intelligence:
            p1.append({
                "title": f"Remediate KEV vulnerability {item.get('cveID', 'Unknown CVE')}",
                "reason": "This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.",
                "action": item.get("requiredAction", "Apply vendor remediation immediately.")
            })

    for asset in hidden_asset_intelligence.get("high_assets", []):
        p2.append({
            "title": f"Review hidden high-risk asset {asset.get('hostname')}",
            "reason": asset.get("risk_reason", "High-risk hidden asset discovered."),
            "action": "Validate ownership, exposure, and monitoring coverage."
        })

    for finding in findings:
        severity = finding.get("severity")
        item = {
            "title": finding.get("finding"),
            "reason": f"{severity} severity finding",
            "action": finding.get("recommendation")
        }

        if severity == "Critical":
            p1.append(item)
        elif severity == "High":
            p2.append(item)
        elif severity in ["Medium", "Low"]:
            p3.append(item)

    return {
        "p1_immediate": p1,
        "p2_high": p2,
        "p3_medium": p3,
        "summary": {
            "p1_count": len(p1),
            "p2_count": len(p2),
            "p3_count": len(p3)
        }
    }
