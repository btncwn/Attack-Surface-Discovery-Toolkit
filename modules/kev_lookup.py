import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get_kev_catalog():
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def correlate_kev(cve_ids):
    kev = get_kev_catalog()

    kev_cves = {
        vuln["cveID"]: vuln
        for vuln in kev.get("vulnerabilities", [])
    }

    matches = []

    for cve in cve_ids:
        if cve in kev_cves:
            matches.append(kev_cves[cve])

    return matches
