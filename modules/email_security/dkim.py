# app/scanner/email_security/dkim.py
"""
DKIM (DomainKeys Identified Mail) scanner.

Fixes applied vs. previous version:
- Use dns.asyncresolver instead of dns.resolver so the `await` calls
  are actually valid coroutines. dns.resolver.resolve() is synchronous
  and is NOT awaitable — `await`-ing it raised
  `TypeError: object Answer can't be used in 'await' expression`,
  meaning DKIM checks never actually completed before.
- Catch specific DNS exceptions instead of a bare `except:` so we
  don't accidentally swallow things like KeyboardInterrupt/SystemExit.
- Deduplicate COMMON_SELECTORS so we don't fire the same DNS query
  twice for selectors shared between providers (e.g. "s1"-"s3" appeared
  in both the Microsoft and SendGrid blocks in the original list).
"""
import asyncio
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver
import dns.exception


@dataclass
class DKIMResult:
    status: str  # "VERIFIED", "NOT_VERIFIED", "ERROR"
    selectors_checked: List[str]
    found_selectors: List[str]
    message: str
    risk_level: str  # "LOW", "MEDIUM", "HIGH"


# DNS exceptions that simply mean "no record here" - expected, not a bug.
_NOT_FOUND_EXCEPTIONS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


class DKIMScanner:
    # Gerçek dünya selector'ları - sürekli güncellenmeli.
    # dict.fromkeys ile sırayı koruyarak tekilleştiriyoruz; orijinal
    # listede "s1"/"s2"/"s3" gibi selector'lar birden fazla provider
    # bloğunda tekrarlanıyordu ve aynı DNS sorgusunu gereksiz yere
    # iki kez atıyorduk.
    _RAW_SELECTORS = [
        # Microsoft 365 / Exchange Online
        "selector1", "selector2", "selector3",
        "s1", "s2", "s3",
        "m1", "m2",

        # Google Workspace
        "google", "gmail", "k1", "k2",
        "202306", "202401",  # Year-month format

        "dkim", "dkim1", "dkim2",

        # Proofpoint
        "pp", "pp1", "pp2",

        # Mimecast
        "mimecast", "mc1", "mc2",

        # Mailgun
        "mailgun", "mg", "mg1",

        # SendGrid
        "sg",

        # Generic / Custom
        "default", "key1", "key2",
    ]
    COMMON_SELECTORS = list(dict.fromkeys(_RAW_SELECTORS))

    # Bilinen provider'lar için selector kalıpları
    PROVIDER_PATTERNS = {
        "microsoft": ["selector1", "selector2", "selector3", "s1", "s2", "s3"],
        "google": ["google", "gmail", "k1", "k2"],
        "proofpoint": ["pp", "pp1", "pp2"],
        "mimecast": ["mimecast", "mc1", "mc2"],
    }

    @classmethod
    async def scan(cls, domain: str) -> DKIMResult:
        """DKIM kayıtlarını daha gerçekçi şekilde kontrol et"""
        found_selectors: List[str] = []
        checked: List[str] = []

        tasks = [
            cls._check_dkim_record(f"{selector}._domainkey.{domain}", selector)
            for selector in cls.COMMON_SELECTORS
        ]
        results = await asyncio.gather(*tasks)

        for selector, found in results:
            checked.append(selector)
            if found:
                found_selectors.append(selector)

        if found_selectors:
            return DKIMResult(
                status="VERIFIED",
                selectors_checked=checked,
                found_selectors=found_selectors,
                message=f"DKIM imzalama aktif. {len(found_selectors)} selector bulundu.",
                risk_level="LOW",
            )

        return DKIMResult(
            status="NOT_VERIFIED",
            selectors_checked=checked,
            found_selectors=[],
            message=(
                "DKIM imzalama doğrulanamadı. Domain'inizde DKIM aktif "
                "olabilir ancak selector bilinmiyor. İletişim kurarak doğrulayın."
            ),
            risk_level="MEDIUM",
        )

    @classmethod
    async def _check_dkim_record(cls, dkim_domain: str, selector: str) -> Tuple[str, bool]:
        """Tek bir DKIM kaydını kontrol et (async-safe)."""
        try:
            answers = await dns.asyncresolver.resolve(dkim_domain, "TXT")
            return (selector, bool(answers))
        except _NOT_FOUND_EXCEPTIONS:
            return (selector, False)
        except dns.exception.DNSException:
            # Beklenmedik ama DNS katmanına ait bir hata. Sessizce yutmak
            # yerine "bulunamadı" say; isterseniz burada loglama ekleyin.
            return (selector, False)

    @classmethod
    async def verify_with_provider(cls, domain: str, provider: str) -> Dict[str, Any]:
        """Belirli bir provider için DKIM kontrolü"""
        if provider not in cls.PROVIDER_PATTERNS:
            return {"error": "Unknown provider"}

        found = []
        for selector in cls.PROVIDER_PATTERNS[provider]:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = await dns.asyncresolver.resolve(dkim_domain, "TXT")
                if answers:
                    found.append({
                        "selector": selector,
                        "record": str(answers[0]),
                    })
            except _NOT_FOUND_EXCEPTIONS:
                continue
            except dns.exception.DNSException:
                continue

        return {
            "provider": provider,
            "selectors_found": found,
            "configured": len(found) > 0,
        }
