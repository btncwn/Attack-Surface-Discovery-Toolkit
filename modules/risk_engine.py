def generate_findings(report_data: dict) -> list:
    findings = []

    tech = report_data.get("technology_fingerprint", {})
    open_ports = report_data.get("open_ports", [])
    subdomains = report_data.get("subdomains", [])
    security_headers = report_data.get("security_headers", {})

    if security_headers and "score" in security_headers:

        header_score = security_headers.get("score", 100)
    missing_headers = security_headers.get("missing_headers", [])

    if header_score <= 40:
        findings.append({
            "severity": "High",
            "finding": f"Poor security headers score: {header_score}/100",
            "recommendation": (
                "Implement missing HTTP security headers such as "
                f"{', '.join(missing_headers)} to reduce browser-based attack surface."
            )
        })

    elif header_score < 70:
        findings.append({
            "severity": "Medium",
            "finding": f"Weak security headers score: {header_score}/100",
            "recommendation": (
                "Review and improve HTTP security headers. Missing headers include: "
                f"{', '.join(missing_headers)}."
            )
        })

    if tech.get("x_frame_options") is None:
        findings.append({
            "severity": "Medium",
            "finding": "Missing X-Frame-Options header",
            "recommendation": "Add X-Frame-Options or CSP frame-ancestors protection."
        })

    if tech.get("x_content_type_options") is None:
        findings.append({
            "severity": "Low",
            "finding": "Missing X-Content-Type-Options header",
            "recommendation": "Add X-Content-Type-Options: nosniff."
        })

    if 80 in open_ports:
        findings.append({
            "severity": "Informational",
            "finding": "HTTP port 80 is open",
            "recommendation": "Ensure HTTP redirects securely to HTTPS."
        })

    for item in subdomains:
        if "autodiscover" in item.get("subdomain", ""):
            findings.append({
                "severity": "Informational",
                "finding": "Microsoft 365 Autodiscover endpoint detected",
                "recommendation": "Ensure Exchange Online and autodiscover settings are securely configured."
            })
            break

    return findings


def calculate_attack_surface_score(findings: list) -> dict:
    score = 100

    severity_weights = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 5,
        "Informational": 2
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        score -= severity_weights.get(severity, 0)

    if score < 0:
        score = 0

    if score >= 85:
        rating = "Low Risk"
    elif score >= 65:
        rating = "Moderate Risk"
    elif score >= 40:
        rating = "High Risk"
    else:
        rating = "Critical Risk"

    return {
        "score": score,
        "rating": rating
    }
