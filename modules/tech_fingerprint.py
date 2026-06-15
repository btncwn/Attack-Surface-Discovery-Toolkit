import requests


def fingerprint_technology(domain: str) -> dict:
    url = f"https://{domain}"

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        headers = response.headers

        return {
            "url": response.url,
            "status_code": response.status_code,
            "server": headers.get("Server"),
            "x_powered_by": headers.get("X-Powered-By"),
            "content_type": headers.get("Content-Type"),
            "strict_transport_security": headers.get("Strict-Transport-Security"),
            "content_security_policy": headers.get("Content-Security-Policy"),
            "x_frame_options": headers.get("X-Frame-Options"),
            "x_content_type_options": headers.get("X-Content-Type-Options"),
        }

    except Exception as e:
        return {
            "error": str(e)
        }
