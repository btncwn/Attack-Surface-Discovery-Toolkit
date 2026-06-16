import requests


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def check_security_headers(domain: str) -> dict:
    url = f"https://{domain}"

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        results = {}
        missing_headers = []

        for header in SECURITY_HEADERS:
            present = header in headers
            results[header] = {
                "present": present,
                "value": headers.get(header, "Missing")
            }

            if not present:
                missing_headers.append(header)

        score = max(0, 100 - (len(missing_headers) * 15))

        return {
            "url": response.url,
            "status_code": response.status_code,
            "score": score,
            "missing_headers": missing_headers,
            "headers": results
        }

    except Exception as e:
        return {"error": str(e)}
