# modules/ct_discovery.py
import requests
import json
import time
from typing import Dict, List, Set


def get_ct_subdomains(domain: str) -> Dict:
    """
    Fetches subdomains from Certificate Transparency logs.

    Args:
        domain: Target domain, for example: example.com

    Returns:
        Dict: {
            "source": "crt.sh",
            "count": int,
            "subdomains": List[str],
            "errors": List[str]
        }
    """
    domain = domain.strip().lower().replace(
        "https://", "").replace("http://", "").strip("/")

    discovered: Set[str] = set()
    errors: List[str] = []

    crt_urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json"
    ]

    for url in crt_urls:
        try:
            response = requests.get(
                url,
                timeout=60,
                headers={
                    "User-Agent": "Mozilla/5.0 (Attack-Surface-Discovery-Toolkit; +https://example.com)"
                }
            )

            if response.status_code != 200:
                errors.append(f"crt.sh returned HTTP {response.status_code}")
                continue

            try:
                data = response.json()
            except json.JSONDecodeError as error:
                errors.append(f"crt.sh JSON parsing failed: {error}")
                continue

            # Normalize the data structure
            if isinstance(data, dict) and "results" in data:
                entries = data["results"]
            elif isinstance(data, list):
                entries = data
            else:
                errors.append("Unexpected data structure from crt.sh")
                continue

            for entry in entries:
                # Check the name_value or name key
                name_value = entry.get("name_value") or entry.get("name") or ""

                for subdomain in name_value.split("\n"):
                    subdomain = subdomain.strip().lower().replace("*.", "")

                    # Check domain match
                    if subdomain and (subdomain == domain or subdomain.endswith(f".{domain}")):
                        discovered.add(subdomain)

            # Rate limiting - be polite to crt.sh
            time.sleep(0.5)

        except requests.exceptions.Timeout:
            errors.append(f"crt.sh request timed out for {url}")
        except requests.exceptions.RequestException as error:
            errors.append(f"crt.sh request failed: {error}")
        except Exception as error:
            errors.append(f"Unexpected error: {error}")

    return {
        "source": "crt.sh",
        "count": len(discovered),
        "subdomains": sorted(discovered),
        "errors": errors
    }
