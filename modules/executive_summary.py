from typing import List, Dict


def generate_executive_summary(report_data: Dict) -> Dict:
    domain = report_data.get("domain", "Unknown")
    score_data = report_data.get("attack_surface_score", {})
    findings = report_data.get("findings", [])
    asset_analysis = report_data.get("asset_analysis", {})
    cve_results = report_data.get("cve_correlation", {})
    open_ports = report_data.get("open_ports", [])
    subdomains = report_data.get("subdomains", [])

    total_findings = len(findings)
    critical_count = sum(
        1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    medium_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")
    informational_count = sum(
        1 for f in findings if f.get("severity") == "Informational")

    critical_findings = sorted(
        [f for f in findings if f.get("severity") in ["Critical", "High"]],
        key=lambda x: {"Critical": 0, "High": 1}.get(x.get("severity", ""), 2)
    )[:5]

    recommendations = []
    for finding in critical_findings[:3]:
        if finding.get("recommendation"):
            recommendations.append({
                "finding": finding.get("finding", ""),
                "recommendation": finding.get("recommendation", "")
            })

    return {
        "domain": domain,
        "score": score_data.get("score", 0),
        "rating": score_data.get("rating", "Unknown"),
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "informational_count": informational_count,
        "critical_findings": critical_findings,
        "recommendations": recommendations,
        "asset_count": len(asset_analysis.get("hidden_assets", [])),
        "subdomain_count": len(subdomains),
        "open_ports_count": len(open_ports),
        "cve_count": sum(len(cves) for cves in cve_results.values()) if cve_results else 0
    }


def prioritize_remediation(findings: List[Dict]) -> List[Dict]:
    severity_priority = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Informational": 5
    }

    prioritized = []

    for finding in findings:
        finding_text = finding.get("finding", "").lower()
        severity = finding.get("severity", "Informational")

        base_priority = severity_priority.get(severity, 5)

        if "exploit" in finding_text and "cve" in finding_text:
            final_priority = 1
        elif "cve" in finding_text and severity in ["Critical", "High"]:
            final_priority = min(base_priority, 2)
        else:
            final_priority = base_priority

        prioritized.append({
            **finding,
            "priority": final_priority,
            "priority_label": f"P{final_priority}",
            "score_impact": _calculate_score_impact(finding)
        })

    return sorted(prioritized, key=lambda x: x["priority"])


def _calculate_score_impact(finding: Dict) -> int:
    severity_impact = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Informational": 1
    }

    severity = finding.get("severity", "Informational")
    return severity_impact.get(severity, 0)
