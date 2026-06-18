"""
Executive Intelligence Layer

Turns technical scan results into business-friendly executive risk drivers.
"""


def generate_executive_intelligence(report_data: dict) -> dict:
    report_data = report_data or {}

    score = report_data.get("attack_surface_score", {})
    findings = report_data.get("findings", [])
    kev_intelligence = report_data.get("kev_intelligence", [])
    hidden_asset_intelligence = report_data.get("hidden_asset_intelligence", {})
    open_ports = report_data.get("open_ports", [])
    email_security = report_data.get("email_security_intelligence", {})

    key_drivers = []
    recommended_actions = []

    if kev_intelligence:
        key_drivers.append(
            f"{len(kev_intelligence)} CISA Known Exploited Vulnerabilities detected"
        )
        recommended_actions.append(
            "Prioritize immediate remediation for KEV-listed vulnerabilities."
        )

    hidden_count = hidden_asset_intelligence.get("total_hidden", 0)
    high_hidden = hidden_asset_intelligence.get("high_count", 0)

    if hidden_count:
        key_drivers.append(
            f"{hidden_count} hidden asset(s) discovered, including {high_hidden} high-risk asset(s)"
        )
        recommended_actions.append(
            "Review hidden assets and add them to continuous monitoring."
        )

    high_findings = [
        f for f in findings
        if f.get("severity") in ["Critical", "High"]
    ]

    if high_findings:
        key_drivers.append(
            f"{len(high_findings)} critical/high security finding(s) require attention"
        )
        recommended_actions.append(
            "Address critical and high findings before medium-priority improvements."
        )

    if open_ports:
        key_drivers.append(
            f"{len(open_ports)} exposed network service(s) detected"
        )

    if email_security:
        email_score = email_security.get("email_security_score")
        email_risk = email_security.get("business_email_risk")

        if email_risk in ["High", "Critical"]:
            key_drivers.append(
                f"Email security risk is {email_risk}"
            )
            recommended_actions.append(
                "Improve email authentication and transport security controls."
            )
        elif email_score is not None:
            key_drivers.append(
                f"Email security score: {email_score}/100"
            )

    if not key_drivers:
        key_drivers.append("No major executive risk drivers identified.")

    if not recommended_actions:
        recommended_actions.append(
            "Continue periodic monitoring and review exposure changes over time."
        )

    return {
        "overall_risk": score.get("rating", "Unknown"),
        "cyber_health_score": score.get("score"),
        "key_drivers": key_drivers,
        "recommended_actions": recommended_actions,
        "executive_summary": (
            f"Overall risk is {score.get('rating', 'Unknown')}. "
            f"{len(key_drivers)} key risk driver(s) were identified."
        )
    }
