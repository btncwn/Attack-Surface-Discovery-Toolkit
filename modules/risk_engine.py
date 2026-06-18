# modules/risk_engine.py

HIGH_RISK_PORTS = {
    445: ("Critical", "SMB service exposed to the internet"),
    3389: ("High", "Remote Desktop service exposed"),
    5900: ("High", "VNC service exposed"),
    1433: ("High", "Microsoft SQL Server exposed"),
    3306: ("High", "MySQL service exposed"),
    5432: ("High", "PostgreSQL service exposed"),
    21: ("Medium", "FTP service exposed"),
    # 22: ("Medium", "SSH service exposed"),  # ❌ KALDIRILDI
    23: ("Medium", "Telnet service exposed"),
    25: ("Medium", "SMTP service exposed"),
    53: ("Medium", "DNS service exposed"),
    69: ("Medium", "TFTP service exposed"),
    111: ("Medium", "RPC service exposed"),
    135: ("Medium", "RPC service exposed"),
    139: ("Medium", "NetBIOS service exposed"),
    161: ("Medium", "SNMP service exposed"),
    389: ("Medium", "LDAP service exposed"),
    636: ("Medium", "LDAPS service exposed"),
    873: ("Medium", "Rsync service exposed"),
    993: ("Informational", "IMAPS service exposed"),
    995: ("Informational", "POP3S service exposed"),
    1521: ("High", "Oracle Database exposed"),
    2049: ("High", "NFS service exposed"),
    2375: ("Critical", "Docker API exposed"),
    2376: ("Critical", "Docker API (TLS) exposed"),
    27017: ("High", "MongoDB service exposed"),
    27018: ("High", "MongoDB shard exposed"),
    27019: ("High", "MongoDB config server exposed"),
    6379: ("High", "Redis service exposed"),
    9200: ("High", "Elasticsearch exposed"),
    9300: ("High", "Elasticsearch transport exposed"),
    11211: ("Medium", "Memcached service exposed"),
    5000: ("Medium", "Python Flask/Django dev server exposed"),
    8080: ("Medium", "Alternative HTTP port exposed"),
    8443: ("Medium", "Alternative HTTPS port exposed"),
    9000: ("Medium", "Alternative HTTP port exposed"),
    9092: ("Medium", "Kafka broker exposed"),
    9093: ("Medium", "Kafka broker (TLS) exposed"),
}

# 🆕 SSH için ayrı bir kontrol (Informational olarak)
SSH_PORT = 22


def generate_findings(report_data: dict) -> list:
    findings = []

    dns_records = report_data.get("dns_records", {})
    ssl_information = report_data.get("ssl_information", {})
    ct_subdomains = report_data.get("certificate_transparency_subdomains", [])

    has_dns = bool(dns_records.get("A") or dns_records.get("AAAA") or dns_records.get("MX") or dns_records.get("NS"))

    if not has_dns and not ct_subdomains and ssl_information.get("error"):
        findings.append({
            "severity": "Unreachable",
            "finding": "Target could not be resolved",
            "recommendation": "Verify the domain spelling and DNS configuration before interpreting security results."
        })
        return findings

    tech = report_data.get("technology_fingerprint", {})
    open_ports = report_data.get("open_ports", [])
    subdomains = report_data.get("subdomains", [])
    security_headers = report_data.get("security_headers", {})
    otx_information = report_data.get("otx_information", {})
    asset_analysis = report_data.get("asset_analysis", {})
    cve_results = report_data.get("cve_correlation", {})

    # 1. Security Headers
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

    # 2. Individual header checks
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

    # 3. HTTP port (Informational) - HIGH_RISK_PORTS'tan ayrı tut
    if 80 in open_ports:
        findings.append({
            "severity": "Informational",
            "finding": "HTTP port 80 is open",
            "recommendation": "Ensure HTTP redirects securely to HTTPS."
        })

    # 4. SSH port (Informational)
    if SSH_PORT in open_ports:
        findings.append({
            "severity": "Informational",
            "finding": "SSH service exposed",
            "recommendation": (
                "Ensure SSH is properly secured with key-based authentication, "
                "fail2ban, and regular updates. Consider using a VPN for administrative access."
            )
        })

    # 5. High risk ports (SSH ve 80 hariç)
    for port in open_ports:
        if port in HIGH_RISK_PORTS and port != 80 and port != SSH_PORT:
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

    # 6. Microsoft 365 Autodiscover
    for item in subdomains:
        if "autodiscover" in item.get("subdomain", ""):
            findings.append({
                "severity": "Informational",
                "finding": "Microsoft 365 Autodiscover endpoint detected",
                "recommendation": "Ensure Exchange Online and autodiscover settings are securely configured."
            })
            break

    # 7. AlienVault OTX Threat Intelligence
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

    # 8. CT-only assets (HIDDEN ASSETS)
    hidden_assets = asset_analysis.get("hidden_assets", [])
    hidden_count = len(hidden_assets)

    if hidden_count > 100:
        findings.append({
            "severity": "High",
            "finding": f"{hidden_count} unmanaged assets discovered via Certificate Transparency logs",
            "recommendation": (
                "Immediately review all CT-discovered assets. Many may be forgotten subdomains, "
                "test environments, or outdated services that pose significant security risks. "
                "Consider implementing automated asset discovery and inventory management."
            )
        })
    elif hidden_count > 25:
        findings.append({
            "severity": "Medium",
            "finding": f"{hidden_count} hidden assets discovered via Certificate Transparency logs",
            "recommendation": (
                "Review unmanaged internet-facing assets. These may include legacy systems, "
                "unmaintained test environments, or services not under security oversight. "
                "Establish a process for regular asset discovery."
            )
        })
    elif hidden_count > 5:
        findings.append({
            "severity": "Low",
            "finding": f"{hidden_count} hidden assets discovered via Certificate Transparency logs",
            "recommendation": (
                "Verify these assets are intended and properly configured. Ensure they are "
                "included in your asset inventory and security monitoring."
            )
        })

    # 9. CVE correlation findings
    if cve_results:
        total_cves = sum(len(cves) for cves in cve_results.values())

        if total_cves > 0:
            # Exploitable CVEs
            exploitable_count = 0
            critical_count = 0

            for tech_name, cves in cve_results.items():
                for cve in cves:
                    if cve.get("has_exploit", False):
                        exploitable_count += 1
                    if cve.get("severity") == "CRITICAL":
                        critical_count += 1

            if exploitable_count > 0:
                findings.append({
                    "severity": "Critical",
                    "finding": f"{exploitable_count} exploitable CVE(s) detected in {total_cves} total CVEs",
                    "recommendation": (
                        "Immediately prioritize patching or mitigating exploitable vulnerabilities. "
                        "Public exploits are available, increasing the risk of automated attacks. "
                        "Check vendor security advisories for patches or workarounds."
                    )
                })
            elif critical_count > 0:
                findings.append({
                    "severity": "High",
                    "finding": f"{critical_count} critical CVE(s) detected in {total_cves} total CVEs",
                    "recommendation": (
                        "Prioritize patching critical vulnerabilities. These CVEs have severe "
                        "CVSS scores and should be addressed as soon as possible. "
                        "Review vendor security advisories for remediation steps."
                    )
                })
            # 🆕 DÜZELTME 3: Sadece anlamlı sayıda CVE varsa finding üret
            elif total_cves >= 5:
                findings.append({
                    "severity": "Medium",
                    "finding": f"{total_cves} known CVE(s) detected across {len(cve_results)} technologies",
                    "recommendation": (
                        "Review the detected CVEs and apply necessary patches or mitigations. "
                        "Consider using a vulnerability management program to track remediation."
                    )
                })

    return findings


def calculate_attack_surface_score(findings: list) -> dict:
    if any(finding.get("severity") == "Unreachable" for finding in findings):
        return {
            "score": None,
            "rating": "Unreachable",
            "status": "scan_failed"
        }

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
