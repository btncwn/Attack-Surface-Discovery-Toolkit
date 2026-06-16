# Attack Surface Discovery Toolkit

A Python-based attack surface discovery and security assessment platform designed to identify externally exposed assets, assess security posture, enrich findings with threat intelligence, and track attack surface changes over time.

## Features

### Attack Surface Discovery

* DNS Enumeration
* WHOIS Intelligence
* SSL Certificate Analysis
* Port Scanning
* Subdomain Enumeration
* Technology Fingerprinting

### Security Assessment

* Security Headers Analysis
* Attack Surface Risk Scoring
* Risk Rating Classification
* Findings and Recommendations Engine

### Threat Intelligence

* AlienVault OTX Threat Intelligence Integration
* Optional Shodan Intelligence Integration

### Historical Analysis

* SQLite Historical Scan Database
* Current vs Previous Scan Comparison
* Risk Trend Visualization

### Reporting

* HTML Report Export
* PDF Report Export
* JSON Report Export

### Dashboard

* Interactive Streamlit Dashboard
* Risk Metrics and Findings
* Historical Scan Tracking
* Threat Intelligence Enrichment

## Technology Stack

* Python
* Streamlit
* SQLite
* AlienVault OTX API
* Shodan API (Optional)
* dnspython
* python-whois
* Requests

## Example Workflow

1. Enter a target domain.
2. Collect DNS, WHOIS, SSL, port, subdomain, and technology data.
3. Perform security header analysis.
4. Enrich findings with threat intelligence.
5. Calculate attack surface risk score.
6. Compare with previous assessments.
7. Export results as HTML, PDF, or JSON reports.

## Use Cases

* Attack Surface Management
* Security Assessments
* Threat Intelligence Enrichment
* Security Posture Monitoring
* Security Research
* Cybersecurity Portfolio Demonstration

## Disclaimer

This project is intended for educational, research, and authorized security assessment purposes only.
