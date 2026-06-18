import requests


def analyze_mta_sts(domain):
    """
    Analyze MTA-STS policy.
    """

    result = {
        "enabled": False,
        "policy_mode": None,
        "mx_patterns": [],
        "max_age": None,
        "errors": []
    }

    try:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

        response = requests.get(
            url,
            timeout=10
        )

        if response.status_code != 200:
            return result

        result["enabled"] = True

        for line in response.text.splitlines():

            line = line.strip()

            if line.startswith("mode:"):
                result["policy_mode"] = line.split(":", 1)[1].strip()

            elif line.startswith("mx:"):
                result["mx_patterns"].append(
                    line.split(":", 1)[1].strip()
                )

            elif line.startswith("max_age:"):
                result["max_age"] = int(
                    line.split(":", 1)[1].strip()
                )

    except Exception as e:
        result["errors"].append(str(e))

    return result
