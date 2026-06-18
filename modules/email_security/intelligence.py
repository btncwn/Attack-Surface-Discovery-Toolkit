"""
Email Security Intelligence Engine

Aggregates SPF, DKIM, DMARC, MTA-STS, TLS-RPT and STARTTLS results into
a single business-friendly email security score.
"""


def build_email_security_intelligence(
    domain: str,
    spf_result: dict = None,
    dkim_result: dict = None,
    dmarc_result: dict = None,
    mta_sts_result: dict = None,
    tls_rpt_result: dict = None,
    starttls_result: dict = None,
    provider_result: dict = None
) -> dict:
    spf_result = spf_result or {}
    dkim_result = dkim_result or {}
    dmarc_result = dmarc_result or {}
    mta_sts_result = mta_sts_result or {}
    tls_rpt_result = tls_rpt_result or {}
    starttls_result = starttls_result or {}
    provider_result = provider_result or {}

    score = 0
    findings = []
    strengths = []

    # SPF - 20 points
    if spf_result.get("status") in ["PASS", "FOUND", "VALID"] or spf_result.get("enabled"):
        score += 20
        strengths.append("SPF record is configured.")
    else:
        findings.append("SPF record is missing or invalid.")

    # DKIM - 15 points
    if dkim_result.get("status") in ["VERIFIED", "PASS", "FOUND"] or dkim_result.get("enabled"):
        score += 15
        strengths.append("DKIM appears to be configured.")
    else:
        findings.append("DKIM could not be verified.")

    # DMARC - 25 points
    dmarc_policy = (
        dmarc_result.get("policy")
        or dmarc_result.get("p")
        or dmarc_result.get("record", {}).get("policy")
    )

    if dmarc_policy in ["reject", "quarantine"]:
        score += 25
        strengths.append(f"DMARC enforcement is enabled with policy '{dmarc_policy}'.")
    elif dmarc_policy == "none":
        score += 10
        findings.append("DMARC is present but policy is set to monitoring only.")
    elif dmarc_result.get("enabled"):
        score += 10
        findings.append("DMARC is present but enforcement could not be confirmed.")
    else:
        findings.append("DMARC record is missing.")

    # MTA-STS - 15 points
    if mta_sts_result.get("enabled"):
        mode = mta_sts_result.get("policy_mode")
        if mode == "enforce":
            score += 15
            strengths.append("MTA-STS is enabled in enforce mode.")
        else:
            score += 8
            findings.append("MTA-STS is enabled but not in enforce mode.")
    else:
        findings.append("MTA-STS is not enabled.")

    # TLS-RPT - 10 points
    if tls_rpt_result.get("enabled"):
        score += 10
        strengths.append("TLS-RPT reporting is configured.")
    else:
        findings.append("TLS-RPT reporting is not configured.")

    # STARTTLS - 15 points
    if starttls_result.get("starttls_supported_hosts", 0) > 0:
        score += 15
        strengths.append("STARTTLS is supported by mail servers.")
    elif starttls_result.get("enabled"):
        score += 15
        strengths.append("STARTTLS is supported.")
    else:
        findings.append("STARTTLS support could not be confirmed.")

    if score >= 90:
        rating = "Excellent"
        risk = "Low"
    elif score >= 75:
        rating = "Good"
        risk = "Low"
    elif score >= 50:
        rating = "Fair"
        risk = "Moderate"
    elif score >= 25:
        rating = "Poor"
        risk = "High"
    else:
        rating = "Critical"
        risk = "Critical"

    return {
        "domain": domain,
        "email_security_score": min(score, 100),
        "rating": rating,
        "business_email_risk": risk,
        "provider": provider_result.get("provider") or provider_result.get("name"),
        "strengths": strengths,
        "findings": findings,
        "components": {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "mta_sts": mta_sts_result,
            "tls_rpt": tls_rpt_result,
            "starttls": starttls_result,
            "provider": provider_result,
        }
    }
