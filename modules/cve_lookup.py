import requests
import time
from typing import Dict, List, Set


def check_exploit_exists(cve_id: str) -> bool:
    """Exploit-DB'de bu CVE için exploit var mı kontrol et."""
    try:
        url = f"https://www.exploit-db.com/search?cve={cve_id}"
        response = requests.get(url, timeout=10, headers={
            "User-Agent": "Mozilla/5.0"
        })
        return "No Results" not in response.text and len(response.text) > 1000
    except:
        return False


def enrich_technology_detection(tech_info: Dict, dns_records: Dict) -> Set[str]:
    """
    Sadece gerçek çalışan teknolojileri tespit et.
    TXT/SPF/Verification kayıtlarını KULLANMA.
    """

    technologies = set()

    # 1. Server Header (EN ÖNEMLİ)
    server = tech_info.get("server", "")
    if server:
        tech = server.split("/")[0].lower()
        # Bilinen web sunucuları
        known_servers = {
            "akamaighost", "apache", "nginx", "iis", "tomcat",
            "jetty", "caddy", "lighttpd", "openresty", "tengine"
        }
        if tech in known_servers or len(tech) >= 3:
            technologies.add(tech)

    # 2. X-Powered-By
    x_powered_by = tech_info.get("x_powered_by", "")
    if x_powered_by:
        tech = x_powered_by.split("/")[0].lower()
        known_tech = {"php", "asp.net", "express", "rails", "django", "flask"}
        if tech in known_tech or len(tech) >= 3:
            technologies.add(tech)

    # 3. Content-Type (sadece net teknolojiler için)
    content_type = tech_info.get("content_type", "")
    if "php" in content_type.lower():
        technologies.add("php")
    elif "asp" in content_type.lower():
        technologies.add("asp.net")

    # 4. URL'den CMS tespiti
    url = tech_info.get("url", "")
    if "wordpress" in url.lower() or "wp-" in url.lower() or "wp/" in url.lower():
        technologies.add("wordpress")
    if "joomla" in url.lower():
        technologies.add("joomla")
    if "drupal" in url.lower():
        technologies.add("drupal")
    if "shopify" in url.lower():
        technologies.add("shopify")

    # 5. CSP Header'dan CDN tespiti (sadece gerçek kullanım)
    csp = tech_info.get("content_security_policy") or ""
    if "cloudflare" in csp.lower():
        technologies.add("cloudflare")
    if "akamai" in csp.lower():
        technologies.add("akamai")

    # ❌ KALDIRILANLAR:
    # - TXT records
    # - SPF
    # - DNS verification kayıtları
    # - Google/Apple/Atlassian verification
    # - Name server'lar

    return technologies


def lookup_cves_for_technology(
    technology_name: str,
    max_results: int = 5,
    severity_filter: str = "HIGH"
) -> List[Dict]:
    """NVD API'den CVE'leri ara."""

    if not technology_name or len(technology_name) < 3:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Teknoloji bazında daha iyi keyword'ler
    keyword_map = {
        "akamaighost": "akamai",
        "akamai": "akamai",
        "apache": "apache http server",
        "nginx": "nginx",
        "iis": "microsoft iis",
        "tomcat": "apache tomcat",
        "jetty": "eclipse jetty",
        "wordpress": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "php": "php",
        "asp.net": "asp.net",
        "cloudflare": "cloudflare",
    }

    keyword = keyword_map.get(technology_name.lower(), technology_name)

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    if severity_filter and severity_filter in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        params["cvssV3Severity"] = severity_filter

    try:
        response = requests.get(url, params=params, timeout=20)

        if response.status_code != 200:
            return []

        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", [])[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "Unknown"
            exploitability_score = None

            if "cvssMetricV31" in metrics:
                metric = metrics["cvssMetricV31"][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "Unknown")
                exploitability_score = metric.get("exploitabilityScore")

            elif "cvssMetricV30" in metrics:
                metric = metrics["cvssMetricV30"][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "Unknown")
                exploitability_score = metric.get("exploitabilityScore")

            elif "cvssMetricV2" in metrics:
                metric = metrics["cvssMetricV2"][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                if cvss_score is not None:
                    if cvss_score >= 7:
                        severity = "HIGH"
                    elif cvss_score >= 4:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

            # Exploit kontrolü (HIGH ve üzeri)
            has_exploit = False
            if severity in ["CRITICAL", "HIGH"] and cvss_score and cvss_score >= 7.0:
                has_exploit = check_exploit_exists(cve_id)
                time.sleep(0.3)

            cves.append({
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "exploitability_score": exploitability_score,
                "has_exploit": has_exploit,
                "description": (
                    description[:300] + "..."
                    if len(description) > 300
                    else description
                )
            })

        return cves

    except Exception:
        return []


def correlate_cves(tech_info: Dict, dns_records: Dict) -> Dict[str, List[Dict]]:
    """Tüm teknolojiler için CVE'leri topla."""

    technologies = enrich_technology_detection(tech_info, dns_records)
    results = {}

    for technology in sorted(technologies):
        time.sleep(0.5)
        cves = lookup_cves_for_technology(technology, severity_filter="HIGH")
        if cves:
            results[technology] = cves

    return results


def get_critical_cves(tech_info: Dict, dns_records: Dict) -> List[Dict]:
    """Sadece CRITICAL CVE'leri döndür."""

    all_cves = correlate_cves(tech_info, dns_records)
    critical_cves = []

    for technology, cves in all_cves.items():
        for cve in cves:
            if cve.get("severity") == "CRITICAL":
                cve["technology"] = technology
                critical_cves.append(cve)

    return sorted(
        critical_cves,
        key=lambda x: x.get("cvss_score", 0),
        reverse=True
    )


def get_exploitable_cves(tech_info: Dict, dns_records: Dict) -> List[Dict]:
    """Exploit'i mevcut olan CVE'leri döndür."""

    all_cves = correlate_cves(tech_info, dns_records)
    exploitable_cves = []

    for technology, cves in all_cves.items():
        for cve in cves:
            if cve.get("has_exploit", False):
                cve["technology"] = technology
                exploitable_cves.append(cve)

    return sorted(
        exploitable_cves,
        key=lambda x: x.get("cvss_score", 0),
        reverse=True
    )
