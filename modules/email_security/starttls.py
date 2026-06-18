import socket
import ssl
import smtplib
import dns.resolver
from datetime import datetime


def get_mx_records(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        return [{"priority": p, "host": h} for p, h in mx_records]
    except Exception as e:
        return []


def test_starttls_host(mx_host: str, timeout: int = 10) -> dict:
    result = {
        "host": mx_host,
        "starttls_supported": False,
        "tls_version": None,
        "cipher": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "certificate_not_after": None,
        "issues": [],
        "error": None,
    }

    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as server:
            server.ehlo()
            if not server.has_extn("starttls"):
                result["issues"].append("STARTTLS is not supported.")
                return result

            result["starttls_supported"] = True

            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()

            sock = server.sock
            result["tls_version"] = sock.version()
            result["cipher"] = sock.cipher()[0] if sock.cipher() else None

            cert = sock.getpeercert()
            if cert:
                result["certificate_subject"] = cert.get("subject")
                result["certificate_issuer"] = cert.get("issuer")
                result["certificate_not_after"] = cert.get("notAfter")

    except Exception as e:
        result["error"] = str(e)
        result["issues"].append(str(e))

    return result


def analyze_starttls(domain: str) -> dict:
    mx_records = get_mx_records(domain)

    results = []
    for mx in mx_records[:5]:
        results.append(test_starttls_host(mx["host"]))

    supported = [r for r in results if r.get("starttls_supported")]
    failed = [r for r in results if not r.get("starttls_supported")]

    score = 0
    if mx_records:
        score += 30
    if results and len(supported) == len(results):
        score += 50
    elif supported:
        score += 25

    if all(r.get("tls_version") in ["TLSv1.2", "TLSv1.3"] for r in supported):
        score += 20

    return {
        "domain": domain,
        "mx_records": mx_records,
        "hosts_tested": results,
        "starttls_supported_hosts": len(supported),
        "starttls_failed_hosts": len(failed),
        "score": min(score, 100),
        "tested_at": datetime.utcnow().isoformat() + "Z",
    }
