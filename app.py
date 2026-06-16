import streamlit as st
import pandas as pd

from modules.dns_lookup import get_dns_records
from modules.whois_lookup import get_whois_info
from modules.ssl_checker import get_ssl_certificate
from modules.port_scanner import scan_ports
from modules.subdomain_enum import enumerate_subdomains
from modules.tech_fingerprint import fingerprint_technology
from modules.risk_engine import generate_findings, calculate_attack_surface_score
from modules.report_generator import save_report
from modules.html_report import generate_html_report
from modules.pdf_report import generate_pdf_report
from modules.database import initialize_database, save_scan_result, get_scan_history, get_previous_scan
from modules.shodan_lookup import get_shodan_info
from modules.security_headers import check_security_headers
from modules.otx_lookup import get_otx_domain_info
from modules.change_detection import compare_findings
from modules.ct_discovery import get_ct_subdomains
from modules.asset_discovery import compare_discovered_assets
from modules.cve_lookup import correlate_cves
from modules.executive_summary import generate_executive_summary, prioritize_remediation

st.set_page_config(
    page_title="Attack Surface Discovery Toolkit",
    page_icon="🛡️",
    layout="wide"
)

initialize_database()

st.title("🛡️ Attack Surface Discovery Toolkit")
st.write("Python-based Attack Surface Management (ASM) and Security Assessment Platform")

domain = st.text_input("Target Domain", placeholder="example.com")
domain = domain.strip().lower()

st.sidebar.header("Threat Intelligence Integrations")

shodan_api_key = st.sidebar.text_input(
    "Shodan API Key (Optional)",
    type="password"
)

otx_api_key = st.sidebar.text_input(
    "AlienVault OTX API Key (Optional)",
    type="password"
)

if st.button("Scan Target"):
    if not domain:
        st.warning("Please enter a domain first.")
    else:
        st.success(f"Starting scan for {domain}")

        dns_records = get_dns_records(domain)
        whois_info = get_whois_info(domain)
        ssl_info = get_ssl_certificate(domain)
        open_ports = scan_ports(domain)
        subdomains = enumerate_subdomains(domain)

        ct_results = get_ct_subdomains(domain)

        ct_subdomains = ct_results.get("subdomains", [])
        ct_errors = ct_results.get("errors", [])
        asset_analysis = compare_discovered_assets(
            subdomains,
            ct_subdomains
        )
        tech_info = fingerprint_technology(domain)
        security_headers = check_security_headers(domain)
        cve_results = correlate_cves(tech_info, dns_records)

        shodan_info = {}
        if shodan_api_key and dns_records.get("A"):
            first_ip = dns_records["A"][0]
            shodan_info = get_shodan_info(first_ip, shodan_api_key)

        otx_info = {}
        if otx_api_key:
            otx_info = get_otx_domain_info(domain, otx_api_key)

        report_data = {
            "domain": domain,
            "dns_records": dns_records,
            "whois_information": whois_info,
            "ssl_information": ssl_info,
            "open_ports": open_ports,
            "subdomains": subdomains,
            "certificate_transparency_subdomains": ct_subdomains,
            "asset_analysis": asset_analysis,
            "technology_fingerprint": tech_info,
            "security_headers": security_headers,
            "shodan_information": shodan_info,
            "certificate_transparency_results": ct_results,
            "otx_information": otx_info,
            "cve_correlation": cve_results,
        }

        findings = generate_findings(report_data)
        report_data["findings"] = findings

        attack_surface_score = calculate_attack_surface_score(findings)
        report_data["attack_surface_score"] = attack_surface_score
        executive_summary = generate_executive_summary(report_data)
        prioritized_findings = prioritize_remediation(findings)
        st.subheader("📋 Executive Summary")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Attack Surface Score",
                      f"{executive_summary['score']}/100")

        with col2:
            st.metric("Risk Rating", executive_summary["rating"])

        with col3:
            st.metric("Total Findings", executive_summary["total_findings"])

        with col4:
            st.metric(
                "Critical / High",
                f"{executive_summary['critical_count']} / {executive_summary['high_count']}"
            )

        st.divider()

        st.write("### 🔍 Critical Findings")

        critical_findings = executive_summary["critical_findings"]

        if critical_findings:
            for finding in critical_findings[:3]:
                severity = finding.get("severity", "")
                finding_text = finding.get("finding", "")
                recommendation = finding.get("recommendation", "")

                if severity == "Critical":
                    st.error(f"**{severity}**: {finding_text}")
                else:
                    st.warning(f"**{severity}**: {finding_text}")

                st.write(f"💡 {recommendation}")
        else:
            st.success("No critical or high findings detected.")

        st.divider()

        st.write("### ⚡ Remediation Prioritization")
        st.write(
            "Prioritize these findings based on severity and expected score impact.")

        for item in prioritized_findings[:8]:
            priority = item.get("priority_label", "P5")
            severity = item.get("severity", "")
            finding_text = item.get("finding", "")
            recommendation = item.get("recommendation", "")
            score_impact = item.get("score_impact", 0)

            if priority == "P1":
                badge = "🔴"
            elif priority == "P2":
                badge = "🟡"
            else:
                badge = "🟢"

            st.write(
                f"{badge} **{priority}** - {severity}: {finding_text} "
                f"(Score impact: +{score_impact})"
            )

            if recommendation:
                st.caption(
                    f"💡 {recommendation[:150]}..."
                    if len(recommendation) > 150
                    else f"💡 {recommendation}"
                )

        with st.expander("📊 Summary Statistics"):
            col1, col2 = st.columns(2)

            with col1:
                st.write(f"**Domain:** {executive_summary['domain']}")
                st.write(
                    f"**Subdomains Found:** {executive_summary['subdomain_count']}")
                st.write(
                    f"**Open Ports:** {executive_summary['open_ports_count']}")

            with col2:
                st.write(
                    f"**Hidden Assets:** {executive_summary['asset_count']}")
                st.write(
                    f"**CVEs Detected:** {executive_summary['cve_count']}")
                st.write(
                    "**Findings:** "
                    f"C:{executive_summary['critical_count']} "
                    f"H:{executive_summary['high_count']} "
                    f"M:{executive_summary['medium_count']} "
                    f"L:{executive_summary['low_count']}"
                )

        save_scan_result(
            domain,
            attack_surface_score["score"],
            attack_surface_score["rating"],
            findings
        )

        html_report = generate_html_report(domain, report_data)
        pdf_report = generate_pdf_report(domain, report_data)
        json_report = save_report(domain, report_data)

        st.subheader("🎯 Attack Surface Score")

        st.metric(
            label="Overall Score",
            value=f"{attack_surface_score['score']}/100"
        )

        st.info(f"Risk Rating: {attack_surface_score['rating']}")

        st.subheader("🚨 Findings")

        if findings:
            for finding in findings:
                st.warning(f"{finding['severity']} - {finding['finding']}")
                st.write(finding["recommendation"])
        else:
            st.success("No basic findings detected.")

        with st.expander("🌐 DNS Records"):
            st.json(dns_records)

        with st.expander("📋 WHOIS Information"):
            st.json(whois_info)

        with st.expander("🔐 SSL Certificate Information"):
            st.json(ssl_info)

        with st.expander("🔓 Open Ports"):
            st.write(open_ports)

        with st.expander("🛰️ Subdomains"):
            st.json(subdomains)

        with st.expander("📜 Certificate Transparency Discovery"):
            st.write(f"Source: {ct_results.get('source')}")
            st.write(f"Discovered {ct_results.get('count')} entries")
            st.json(ct_subdomains)

            if ct_results.get("errors"):
                st.warning(
                    "Certificate Transparency lookup completed with warnings.")
                st.json(ct_results.get("errors"))

        with st.expander("⚙️ Technology Fingerprint"):
            st.json(tech_info)

        with st.expander("🧬 CVE Correlation Engine"):

            if cve_results:

                total_cves = sum(
                    len(cves)
                    for cves in cve_results.values()
                )

                critical_cves = []
                exploitable_cves = []

                for technology, cves in cve_results.items():

                    for cve in cves:

                        cve_with_technology = cve.copy()
                        cve_with_technology["technology"] = technology

                        if cve.get("severity") == "CRITICAL":
                            critical_cves.append(cve_with_technology)

                        if cve.get("has_exploit"):
                            exploitable_cves.append(cve_with_technology)

                st.write(
                    f"🔍 Found {total_cves} CVEs across {len(cve_results)} detected technologies."
                )

                if exploitable_cves:

                    st.error(
                        f"🚨 {len(exploitable_cves)} exploitable CVE(s) detected."
                    )

                    for cve in exploitable_cves[:5]:

                        st.warning(
                            f"💀 {cve['cve_id']} ({cve['technology']}) - CVSS: {cve.get('cvss_score')}"
                        )

                        st.caption(
                            cve.get("description", "")
                        )

                elif critical_cves:

                    st.warning(
                        f"⚠️ {len(critical_cves)} critical CVE(s) detected."
                    )

                    for cve in critical_cves[:5]:

                        st.write(
                            f"🔴 {cve['cve_id']} ({cve['technology']}) - CVSS: {cve.get('cvss_score')}"
                        )

                        st.caption(
                            cve.get("description", "")
                        )

                for technology, cves in cve_results.items():

                    st.markdown(f"### 🔍 {technology.upper()}")

                    for cve in cves:

                        emoji = "🔴" if cve.get(
                            "severity") == "CRITICAL" else "🟡"

                        exploit_emoji = " 💀" if cve.get("has_exploit") else ""

                        st.write(
                            f"{emoji} **{cve.get('cve_id')}** - CVSS: {cve.get('cvss_score')} ({cve.get('severity')}){exploit_emoji}"
                        )

                        st.caption(
                            cve.get("description", "")
                        )

            else:

                st.info(
                    "No high-severity CVE correlation results found for detected technologies."
                )

        with st.expander("🛡️ Security Headers Analysis"):
            st.json(security_headers)

        with st.expander("🌍 Shodan Intelligence"):
            if shodan_info:
                st.json(shodan_info)
            else:
                st.info(
                    "No Shodan API key provided, no A record found, or API plan does not support host lookup.")

        with st.expander("🛰️ AlienVault OTX Threat Intelligence"):
            if otx_info:
                st.json(otx_info)
            else:
                st.info("No AlienVault OTX API key provided.")

        with st.expander("🕵️ Hidden Asset Discovery"):
            hidden_assets = asset_analysis["hidden_assets"]
            st.write(f"Discovered {len(hidden_assets)} CT-only assets")

            if hidden_assets:
                st.warning(
                    "⚠️ These assets were found in Certificate Transparency logs but NOT in standard enumeration")

        # DataFrame ile göster
        import pandas as pd
        df = pd.DataFrame(hidden_assets, columns=["Hidden Subdomains"])
        st.dataframe(df, use_container_width=True, height=300)

        # CSV export
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download Hidden Assets CSV",
            data=csv,
            file_name=f"{domain}_hidden_assets.csv",
            mime="text/csv"
        )

        st.subheader("🔍 Current vs Previous Scan")

        previous_scan = get_previous_scan(domain)

        if previous_scan:
            previous_date = previous_scan[0]
            previous_score = previous_scan[1]
            previous_rating = previous_scan[2]
            previous_findings_json = previous_scan[3]

            current_score = attack_surface_score["score"]
            score_change = current_score - previous_score

            st.write(f"Previous Scan Date: {previous_date}")
            st.write(f"Previous Score: {previous_score}/100")
            st.write(f"Previous Rating: {previous_rating}")
            st.write(f"Current Score: {current_score}/100")

            if score_change > 0:
                st.success(f"Risk score improved by {score_change} points.")
            elif score_change < 0:
                st.error(
                    f"Risk score decreased by {abs(score_change)} points.")
            else:
                st.info("No score change since the previous scan.")

            exposure_changes = compare_findings(
                findings, previous_findings_json)

            st.subheader("🧭 Exposure Change Detection")

            if exposure_changes["new_findings"]:
                st.error("New Findings Detected")
                for item in exposure_changes["new_findings"]:
                    st.write(f"➕ {item}")

            if exposure_changes["resolved_findings"]:
                st.success("Resolved Findings")
                for item in exposure_changes["resolved_findings"]:
                    st.write(f"✅ {item}")

            if not exposure_changes["new_findings"] and not exposure_changes["resolved_findings"]:
                st.info("No exposure changes detected since the previous scan.")

        else:
            st.info("No previous scan available for comparison.")

        st.subheader("📈 Historical Scan Results")

        history = get_scan_history(domain)

        if history:
            chart_data = pd.DataFrame(
                [
                    {
                        "Scan Date": row[0],
                        "Score": row[1]
                    }
                    for row in history
                ]
            )

            chart_data = chart_data.sort_values(by="Scan Date")
            chart_data = chart_data.set_index("Scan Date")

            st.subheader("📊 Risk Trend")
            st.line_chart(chart_data)

            st.table(
                [
                    {
                        "Scan Date": row[0],
                        "Score": row[1],
                        "Rating": row[2]
                    }
                    for row in history
                ]
            )
        else:
            st.info("No previous scan history found.")

        st.subheader("📄 Reports")

        with open(html_report, "rb") as file:
            st.download_button(
                label="Download HTML Report",
                data=file,
                file_name=f"{domain}_report.html",
                mime="text/html"
            )

        with open(pdf_report, "rb") as file:
            st.download_button(
                label="Download PDF Report",
                data=file,
                file_name=f"{domain}_report.pdf",
                mime="application/pdf"
            )

        with open(json_report, "rb") as file:
            st.download_button(
                label="Download JSON Report",
                data=file,
                file_name=f"{domain}_report.json",
                mime="application/json"
            )
