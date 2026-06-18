import requests
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-frame-options": "Frame Options",
    "x-content-type-options": "Content Type Options",
    "referrer-policy": "Referrer Policy",
    "permissions-policy": "Permissions Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "cross-origin-embedder-policy": "COEP",
}


def fetch_headers(domain: str, timeout: int = 10) -> dict:
    url = domain if domain.startswith("http") else f"https://{domain}"

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": {k.lower(): v for k, v in response.headers.items()},
            "error": None,
        }
    except Exception as e:
        return {
            "url": url,
            "final_url": None,
            "status_code": None,
            "headers": {},
            "error": str(e),
        }


def analyze_hsts(headers: dict) -> dict:
    value = headers.get("strict-transport-security")

    result = {
        "enabled": bool(value),
        "value": value,
        "max_age": None,
        "include_subdomains": False,
        "preload_directive": False,
        "issues": [],
        "score": 0,
    }

    if not value:
        result["issues"].append("HSTS header is missing.")
        return result

    lower = value.lower()

    if "includesubdomains" in lower:
        result["include_subdomains"] = True
    else:
        result["issues"].append("HSTS includeSubDomains directive is missing.")

    if "preload" in lower:
        result["preload_directive"] = True
    else:
        result["issues"].append("HSTS preload directive is missing.")

    for part in lower.split(";"):
        part = part.strip()
        if part.startswith("max-age"):
            try:
                result["max_age"] = int(part.split("=")[1])
            except Exception:
                result["issues"].append("HSTS max-age value could not be parsed.")

    if result["max_age"] is None:
        result["issues"].append("HSTS max-age is missing.")
    elif result["max_age"] < 31536000:
        result["issues"].append("HSTS max-age is less than 1 year.")

    score = 40
    if result["max_age"] and result["max_age"] >= 31536000:
        score += 25
    if result["include_subdomains"]:
        score += 20
    if result["preload_directive"]:
        score += 15

    result["score"] = min(score, 100)
    return result


def analyze_csp(headers: dict) -> dict:
    value = headers.get("content-security-policy")

    result = {
        "enabled": bool(value),
        "value": value,
        "issues": [],
        "strength": "Missing",
        "score": 0,
    }

    if not value:
        result["issues"].append("Content-Security-Policy header is missing.")
        return result

    lower = value.lower()
    score = 40

    if "default-src" in lower:
        score += 15
    else:
        result["issues"].append("CSP default-src directive is missing.")

    if "script-src" in lower:
        score += 15
    else:
        result["issues"].append("CSP script-src directive is missing.")

    if "object-src 'none'" in lower or "object-src none" in lower:
        score += 10
    else:
        result["issues"].append("CSP object-src 'none' is missing.")

    if "base-uri" in lower:
        score += 10
    else:
        result["issues"].append("CSP base-uri directive is missing.")

    if "'unsafe-inline'" in lower:
        score -= 15
        result["issues"].append("CSP allows unsafe-inline.")

    if "'unsafe-eval'" in lower:
        score -= 15
        result["issues"].append("CSP allows unsafe-eval.")

    score = max(0, min(score, 100))
    result["score"] = score

    if score >= 80:
        result["strength"] = "Strong"
    elif score >= 50:
        result["strength"] = "Moderate"
    else:
        result["strength"] = "Weak"

    return result


def analyze_security_headers(headers: dict) -> dict:
    present = {}
    missing = []

    for header, name in SECURITY_HEADERS.items():
        if header in headers:
            present[name] = headers.get(header)
        else:
            missing.append(name)

    score = int((len(present) / len(SECURITY_HEADERS)) * 100)

    return {
        "present": present,
        "missing": missing,
        "score": score,
    }


def analyze_web_security(domain: str) -> dict:
    fetched = fetch_headers(domain)
    headers = fetched.get("headers", {})

    hsts = analyze_hsts(headers)
    csp = analyze_csp(headers)
    security_headers = analyze_security_headers(headers)

    overall_score = int(
        (hsts["score"] * 0.35) +
        (csp["score"] * 0.35) +
        (security_headers["score"] * 0.30)
    )

    return {
        "domain": domain,
        "final_url": fetched.get("final_url"),
        "status_code": fetched.get("status_code"),
        "error": fetched.get("error"),
        "hsts": hsts,
        "csp": csp,
        "security_headers": security_headers,
        "web_security_score": overall_score,
    }
