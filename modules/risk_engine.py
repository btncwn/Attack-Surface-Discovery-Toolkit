def generate_findings(report_data: dict) -> list:
    findings = []

    tech = report_data.get("technology_fingerprint", {})
    open_ports = report_data.get("open_ports", [])
    subdomains = report_data.get("subdomains", [])

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
