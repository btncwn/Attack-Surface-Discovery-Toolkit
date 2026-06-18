# app/scanner/email_security/dmarc.py
"""
DMARC scanner.

Fix applied vs. previous version: dns.resolver.resolve() is synchronous
and is NOT awaitable. `await dns.resolver.resolve(...)` raised
`TypeError: object Answer can't be used in 'await' expression` at
runtime, meaning DMARC checks silently never actually ran. Switched to
dns.asyncresolver, which provides a real coroutine, and narrowed the
bare-ish exception handling to specific DNS exceptions.
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver
import dns.exception


@dataclass
class DMARCResult:
    status: str  # "FULLY_PROTECTED", "PARTIAL_PROTECTED", "REPORTING_ONLY", "MISSING", "ERROR"
    policy: Optional[str]
    subdomain_policy: Optional[str]
    pct: int  # 0-100
    rua: Optional[str]  # Raporlama email'i
    ruf: Optional[str]  # Forensik rapor email'i
    message: str
    risk_level: str


_NOT_FOUND_EXCEPTIONS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
)


class DMARCScanner:
    @classmethod
    async def scan(cls, domain: str) -> DMARCResult:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await dns.asyncresolver.resolve(dmarc_domain, "TXT")

            if not answers:
                return cls._missing_result()

            dmarc_record = str(answers[0])
            parsed = cls._parse_dmarc(dmarc_record)

            # pct varsayılan 100
            pct = parsed.get("pct", 100)
            policy = parsed.get("p", "none")

            if policy == "reject" and pct == 100:
                status = "FULLY_PROTECTED"
                risk_level = "LOW"
                message = "Tam DMARC koruması aktif."
            elif policy == "reject" and pct < 100:
                status = "PARTIAL_PROTECTED"
                risk_level = "MEDIUM"
                message = f"DMARC koruması kısmi (%{pct} uygulanıyor)."
            elif policy == "quarantine" and pct == 100:
                status = "PARTIAL_PROTECTED"
                risk_level = "MEDIUM"
                message = "Quarantine politikası aktif. Tam koruma için p=reject önerilir."
            elif policy == "quarantine" and pct < 100:
                status = "PARTIAL_PROTECTED"
                risk_level = "HIGH"
                message = f"Quarantine politikası kısmi (%{pct} uygulanıyor)."
            elif policy == "none":
                status = "REPORTING_ONLY"
                risk_level = "HIGH"
                message = "DMARC sadece raporlama modunda. Koruma yok."
            else:
                status = "ERROR"
                risk_level = "HIGH"
                message = f"Bilinmeyen DMARC politikası: {policy}"

            return DMARCResult(
                status=status,
                policy=policy,
                subdomain_policy=parsed.get("sp"),
                pct=pct,
                rua=parsed.get("rua"),
                ruf=parsed.get("ruf"),
                message=message,
                risk_level=risk_level,
            )

        except _NOT_FOUND_EXCEPTIONS:
            return cls._missing_result()
        except dns.exception.DNSException as e:
            return DMARCResult(
                status="ERROR",
                policy=None,
                subdomain_policy=None,
                pct=0,
                rua=None,
                ruf=None,
                message=f"DMARC kontrolü hatası: {str(e)}",
                risk_level="HIGH",
            )

    @classmethod
    def _parse_dmarc(cls, record: str) -> Dict[str, Any]:
        """DMARC kaydını parse et"""
        parsed: Dict[str, Any] = {}
        parts = record.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.lower().strip()
                value = value.strip().strip('"')

                if key in ["p", "sp", "rua", "ruf"]:
                    parsed[key] = value
                elif key == "pct":
                    try:
                        parsed[key] = int(value)
                    except ValueError:
                        parsed[key] = 100
                else:
                    parsed[key] = value
        return parsed

    @classmethod
    def _missing_result(cls) -> DMARCResult:
        return DMARCResult(
            status="MISSING",
            policy=None,
            subdomain_policy=None,
            pct=0,
            rua=None,
            ruf=None,
            message="DMARC kaydı bulunamadı. Email spoofing riski yüksek.",
            risk_level="CRITICAL",
        )
