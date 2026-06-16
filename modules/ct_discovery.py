import requests


def get_ct_subdomains(domain: str) -> list:
    domain = domain.strip().lower().replace(
        "https://", "").replace("http://", "").strip("/")

    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json"
    ]

    discovered = set()

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=30,
                headers={
                    "User-Agent": "Mozilla/5.0 Attack-Surface-Discovery-Toolkit"
                }
            )

            if response.status_code != 200:
                continue

            try:
                data = response.json()
            except Exception:
                continue

            for entry in data:
                name_value = entry.get("name_value", "")

                for subdomain in name_value.split("\n"):
                    subdomain = subdomain.strip().lower()
                    subdomain = subdomain.replace("*.", "")

                    if subdomain.endswith(domain):
                        discovered.add(subdomain)

        except Exception:
            continue

    return sorted(discovered)
