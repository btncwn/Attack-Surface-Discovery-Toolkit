HIGH_RISK_PORTS = {
    445: ("Critical", "SMB service exposed to the internet"),
    3389: ("High", "Remote Desktop service exposed"),
    5900: ("High", "VNC service exposed"),
    1433: ("High", "Microsoft SQL Server exposed"),
    3306: ("High", "MySQL service exposed"),
    5432: ("High", "PostgreSQL service exposed"),
    21: ("Medium", "FTP service exposed"),
    22: ("Medium", "SSH service exposed"),
}


def generate_findings(report_data: dict) -> list:
    findings = []

    tech = report_data.get("technology_fingerprint", {})
    open_ports = report_data.get("open_ports", [])
    subdomains = report_data.get("subdomains", [])
    security_headers = report_data.get("security_headers", {})
    otx_information = report_data.get("otx_information", {})

    header_score = 100
    missing_headers = []

    if security_headers:
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

    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            severity, description = HIGH_RISK_PORTS[port]

            findings.append({
                "severity": severity,
                "finding": description,
                "recommendation": (
                    "Review this exposed service and restrict public internet access "
                    "if it is not explicitly required. Prefer VPN, allowlisting, "
                    "strong authentication, and monitoring for administrative services."
                )
            })

    for item in subdomains:
        if "autodiscover" in item.get("subdomain", ""):
            findings.append({
                "severity": "Informational",
                "finding": "Microsoft 365 Autodiscover endpoint detected",
                "recommendation": "Ensure Exchange Online and autodiscover settings are securely configured."
            })
            break

    pulse_count = otx_information.get("pulse_count", 0)

    if pulse_count >= 20:
        findings.append({
            "severity": "High",
            "finding": f"High AlienVault OTX threat intelligence exposure: {pulse_count} related pulses",
            "recommendation": (
                "Review related OTX pulses to determine whether this domain or associated infrastructure "
                "has been observed in suspicious or malicious activity."
            )
        })

    elif pulse_count >= 5:
        findings.append({
            "severity": "Medium",
            "finding": f"Moderate AlienVault OTX threat intelligence exposure: {pulse_count} related pulses",
            "recommendation": (
                "Review AlienVault OTX context and investigate whether the related pulses are relevant "
                "to this organisation."
            )
        })

    elif pulse_count > 0:
        findings.append({
            "severity": "Low",
            "finding": f"Low AlienVault OTX threat intelligence exposure: {pulse_count} related pulse(s)",
            "recommendation": (
                "Review the OTX pulse details for context and monitor for changes over time."
            )
        })

    return findings


def calculate_attack_surface_score(findings: list) -> dict:
    score = 100

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Informational": 1
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
