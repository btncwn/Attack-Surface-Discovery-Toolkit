import requests


def get_otx_domain_info(domain: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "OTX API key not provided"}

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    headers = {
        "X-OTX-API-KEY": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return {
                "error": f"OTX API returned status code {response.status_code}",
                "details": response.text[:300]
            }

        data = response.json()

        return {
            "indicator": data.get("indicator"),
            "type": data.get("type"),
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "related_pulses": [
                {
                    "name": pulse.get("name"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse.get("tags", [])
                }
                for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]
            ],
            "sections": data.get("sections", [])
        }

    except Exception as e:
        return {"error": str(e)}
