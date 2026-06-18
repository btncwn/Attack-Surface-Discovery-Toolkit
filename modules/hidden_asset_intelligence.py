from datetime import datetime
# modules/hidden_asset_intelligence.py

class HiddenAssetIntelligence:
    """
    Sprint 5 - Certificate Transparency-based hidden asset discovery
    With risk classification
    """

    RISK_LEVELS = {
        "CRITICAL": {
            "patterns": ["admin", "portal", "dashboard", "manager"],
            "reason": "Admin panel or management interface. High risk of unauthorized access."
        },
        "HIGH": {
            "patterns": ["email", "mail", "autodiscover", "api", "auth", "login"],
            "reason": "Email/API/Auth subdomain. Phishing or data leakage risk."
        },
        "MEDIUM": {
            "patterns": ["test", "dev", "stage", "staging", "demo"],
            "reason": "Test/development environment. May contain sensitive data or security weaknesses."
        },
        "LOW": {
            "patterns": ["cdn", "static", "assets", "img", "files"],
            "reason": "CDN or static asset. Low risk but should be included in the inventory."
        }
    }

    @classmethod
    def analyze(cls, domain: str, ct_assets: list, known_assets: list) -> dict:
        """Hidden asset analizi"""

        # CT'de olup known'da olmayanlar
        known_set = set(known_assets)
        ct_set = set(ct_assets)
        hidden = ct_set - known_set

        # Risk analysis for each asset
        classified = []
        for asset in hidden:
            risk = cls._classify_risk(asset)
            classified.append({
                "hostname": asset,
                "risk_level": risk["level"],
                "risk_reason": risk["reason"],
                "source": "Certificate Transparency",
                "discovered_at": datetime.now().isoformat()
            })

        # İstatistikler
        critical = [a for a in classified if a["risk_level"] == "CRITICAL"]
        high = [a for a in classified if a["risk_level"] == "HIGH"]
        medium = [a for a in classified if a["risk_level"] == "MEDIUM"]
        low = [a for a in classified if a["risk_level"] == "LOW"]

        return {
            "total_hidden": len(classified),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "assets": classified,
            "critical_assets": critical,
            "high_assets": high,
            "summary": cls._generate_summary(classified)
        }

    @classmethod
    def _classify_risk(cls, hostname: str) -> dict:
        """Risk seviyesini belirle"""
        hostname_lower = hostname.lower()

        for level, config in cls.RISK_LEVELS.items():
            for pattern in config["patterns"]:
                if pattern in hostname_lower:
                    return {
                        "level": level,
                        "reason": config["reason"]
                    }

        return {
            "level": "LOW",
            "reason": "This asset appears in Certificate Transparency logs but not in standard DNS enumeration."
        }

    @classmethod
    def _generate_summary(cls, assets: list) -> str:
        """Özet metin"""
        critical = sum(1 for a in assets if a["risk_level"] == "CRITICAL")
        high = sum(1 for a in assets if a["risk_level"] == "HIGH")

        if critical > 0:
            return f"⚠️ {len(assets)} hidden asset discovered ({critical} critical, {high} high risk). These assets are not visible in standard enumeration and represent unknown attack surface."
        elif high > 0:
            return f"⚠️ {len(assets)} hidden asset discovered ({high} high risk). Consider adding these to regular monitoring."
        else:
            return f"ℹ️ {len(assets)} hidden asset discovered. Low to medium risk but should be included in asset inventory."
