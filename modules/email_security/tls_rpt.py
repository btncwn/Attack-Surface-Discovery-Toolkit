"""
TLS-RPT Analysis Module

Checks SMTP TLS Reporting DNS policy:
_smtp._tls.<domain> TXT
"""

import dns.resolver


def analyze_tls_rpt(domain: str) -> dict:
    result = {
        "enabled": False,
        "record_name": f"_smtp._tls.{domain}",
        "record": None,
        "reporting_uris": [],
        "errors": []
    }

    try:
        answers = dns.resolver.resolve(result["record_name"], "TXT")

        records = []
        for answer in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else str(part)
                for part in answer.strings
            )
            records.append(txt)

        for record in records:
            if record.lower().startswith("v=tlsrptv1"):
                result["enabled"] = True
                result["record"] = record

                for part in record.split(";"):
                    part = part.strip()
                    if part.lower().startswith("rua="):
                        uris = part.split("=", 1)[1]
                        result["reporting_uris"] = [
                            uri.strip()
                            for uri in uris.split(",")
                            if uri.strip()
                        ]

                return result

        result["errors"].append("No valid TLS-RPT record found.")

    except Exception as e:
        result["errors"].append(str(e))

    return result
