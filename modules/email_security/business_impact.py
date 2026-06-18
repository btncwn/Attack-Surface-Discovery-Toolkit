from dataclasses import dataclass
from typing import Dict, List


@dataclass
class BusinessImpact:
    technical: str
    risk_level: str
    business_impact: str
    recommendation: str


class BusinessImpactEngine:
    """
    Converts technical email-security findings into business-friendly impact statements.
    """

    @staticmethod
    def generate(results: Dict) -> List[BusinessImpact]:
        impacts: List[BusinessImpact] = []

        dmarc = results.get("dmarc", {})
        dkim = results.get("dkim", {})
        spf = results.get("spf", {})
        mta_sts = results.get("mta_sts", {})
        tls_rpt = results.get("tls_rpt", {})

        # DMARC
        if dmarc.get("status") == "MISSING":
            impacts.append(BusinessImpact(
                technical="DMARC Missing",
                risk_level="CRITICAL",
                business_impact=(
                    "Attackers may impersonate your company and send fraudulent "
                    "emails to customers, suppliers, or staff."
                ),
                recommendation=(
                    "Add a DMARC record and move towards p=reject after validating "
                    "legitimate email sources."
                )
            ))

        elif dmarc.get("status") == "REPORTING_ONLY":
            impacts.append(BusinessImpact(
                technical="DMARC Reporting Only",
                risk_level="HIGH",
                business_impact=(
                    "Your domain is collecting DMARC reports but is not actively "
                    "blocking spoofed emails."
                ),
                recommendation=(
                    "Move from p=none to p=quarantine, then to p=reject once email "
                    "flows are validated."
                )
            ))

        elif dmarc.get("status") == "PARTIAL_PROTECTED":
            impacts.append(BusinessImpact(
                technical="DMARC Partial Protection",
                risk_level=dmarc.get("risk_level", "MEDIUM"),
                business_impact=(
                    "Some spoofed emails may still be delivered because DMARC is not "
                    "fully enforced across all messages."
                ),
                recommendation=(
                    "Increase DMARC enforcement to p=reject with pct=100 where safe."
                )
            ))

        # DKIM
        if dkim.get("status") == "NOT_VERIFIED":
            impacts.append(BusinessImpact(
                technical="DKIM Not Verified",
                risk_level="MEDIUM",
                business_impact=(
                    "Your email authentication could not be confirmed from common "
                    "DKIM selectors. This may affect trust and deliverability."
                ),
                recommendation=(
                    "Verify DKIM signing with your email provider and publish the "
                    "correct DKIM DNS records."
                )
            ))

        elif dkim.get("status") == "ERROR":
            impacts.append(BusinessImpact(
                technical="DKIM Check Error",
                risk_level="MEDIUM",
                business_impact=(
                    "DKIM status could not be reliably checked, so email signing "
                    "confidence is reduced."
                ),
                recommendation="Review DKIM DNS configuration with your email provider."
            ))

        # SPF
        if spf.get("status") == "MISSING":
            impacts.append(BusinessImpact(
                technical="SPF Missing",
                risk_level="HIGH",
                business_impact=(
                    "Mail servers may not know which systems are allowed to send "
                    "email on behalf of your domain."
                ),
                recommendation=(
                    "Publish an SPF TXT record listing authorised sending services."
                )
            ))

        elif spf.get("status") == "SOFTFAIL":
            impacts.append(BusinessImpact(
                technical="SPF SoftFail",
                risk_level="MEDIUM",
                business_impact=(
                    "Your SPF record is not fully strict, which may reduce protection "
                    "against spoofed email."
                ),
                recommendation="Consider changing ~all to -all after testing."
            ))

        elif spf.get("status") == "FAIL":
            impacts.append(BusinessImpact(
                technical="SPF Permissive Policy",
                risk_level="HIGH",
                business_impact=(
                    "Your SPF policy may allow unauthorised systems to send email "
                    "using your domain."
                ),
                recommendation="Remove permissive mechanisms such as +all."
            ))

        # MTA-STS
        if mta_sts.get("status") == "MISSING":
            impacts.append(BusinessImpact(
                technical="MTA-STS Missing",
                risk_level="LOW",
                business_impact=(
                    "Inbound email transport encryption is not strictly enforced, "
                    "which can reduce resilience against downgrade attacks."
                ),
                recommendation=(
                    "Consider enabling MTA-STS after SPF, DKIM, and DMARC are stable."
                )
            ))

        # TLS-RPT
        if tls_rpt.get("status") == "MISSING":
            impacts.append(BusinessImpact(
                technical="TLS-RPT Missing",
                risk_level="LOW",
                business_impact=(
                    "You may not receive reports about email TLS delivery problems."
                ),
                recommendation=(
                    "Consider adding TLS-RPT so delivery security issues can be monitored."
                )
            ))

        return impacts


def impacts_to_dict(impacts: List[BusinessImpact]) -> List[Dict]:
    return [impact.__dict__ for impact in impacts]
