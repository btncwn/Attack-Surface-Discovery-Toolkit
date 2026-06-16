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
        tech_info = fingerprint_technology(domain)

        security_headers = check_security_headers(domain)

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
            "technology_fingerprint": tech_info,
            "security_headers": security_headers,
            "shodan_information": shodan_info,
            "otx_information": otx_info
        }

        findings = generate_findings(report_data)
        report_data["findings"] = findings

        attack_surface_score = calculate_attack_surface_score(findings)
        report_data["attack_surface_score"] = attack_surface_score

        save_scan_result(
            domain,
            attack_surface_score["score"],
            attack_surface_score["rating"]
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

        with st.expander("⚙️ Technology Fingerprint"):
            st.json(tech_info)

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

        st.subheader("🔍 Current vs Previous Scan")

        previous_scan = get_previous_scan(domain)

        if previous_scan:
            previous_date = previous_scan[0]
            previous_score = previous_scan[1]
            previous_rating = previous_scan[2]

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
