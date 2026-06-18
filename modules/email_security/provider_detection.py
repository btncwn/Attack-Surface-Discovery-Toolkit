from dataclasses import dataclass
from modules.dns_lookup import get_dns_records


@dataclass
class ProviderResult:
    provider: str
    confidence: str
    details: str


class EmailProviderDetector:

    @staticmethod
    async def detect(domain: str) -> ProviderResult:

        dns_records = get_dns_records(domain)
        mx_records = dns_records.get("MX", [])

        mx_text = " ".join(mx_records).lower()

        # Microsoft 365
        if "protection.outlook.com" in mx_text:
            return ProviderResult(
                provider="Microsoft 365",
                confidence="HIGH",
                details="MX records indicate Microsoft 365 email hosting"
            )

        # Google Workspace
        if (
            "google.com" in mx_text
            or "aspmx.l.google.com" in mx_text
        ):
            return ProviderResult(
                provider="Google Workspace",
                confidence="HIGH",
                details="MX records indicate Google Workspace email hosting"
            )

        # Proofpoint
        if "pphosted.com" in mx_text:
            return ProviderResult(
                provider="Proofpoint",
                confidence="HIGH",
                details="MX records indicate Proofpoint email security"
            )

        # Mimecast
        if "mimecast" in mx_text:
            return ProviderResult(
                provider="Mimecast",
                confidence="HIGH",
                details="MX records indicate Mimecast email security"
            )

        # Zoho
        if "zoho" in mx_text:
            return ProviderResult(
                provider="Zoho Mail",
                confidence="MEDIUM",
                details="MX records indicate Zoho Mail"
            )

        return ProviderResult(
            provider="Custom / Unknown",
            confidence="LOW",
            details="No known email provider detected"
        )
