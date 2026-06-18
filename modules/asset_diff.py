# modules/asset_diff.py

class AssetDiff:
    """
    Sprint 6 - Zaman içindeki değişiklikleri tespit et
    """

    @classmethod
    def compare(cls, current: dict, previous: dict) -> dict:
        """
        İki scan arasındaki farkları bul

        Returns:
            {
                "new_assets": [...],
                "removed_assets": [...],
                "new_ports": [...],
                "removed_ports": [...],
                "ssl_changes": {...},
                "tech_changes": {...}
            }
        """

        result = {
            "new_assets": [],
            "removed_assets": [],
            "new_ports": [],
            "removed_ports": [],
            "ssl_changes": {},
            "tech_changes": {}
        }

        # Asset karşılaştırması
        current_subdomains = set(current.get("subdomains", []))
        previous_subdomains = set(previous.get("subdomains", []))

        result["new_assets"] = list(current_subdomains - previous_subdomains)
        result["removed_assets"] = list(
            previous_subdomains - current_subdomains)

        # Port karşılaştırması
        current_ports = set(current.get("open_ports", []))
        previous_ports = set(previous.get("open_ports", []))

        result["new_ports"] = list(current_ports - previous_ports)
        result["removed_ports"] = list(previous_ports - current_ports)

        # SSL değişiklikleri
        current_ssl = current.get("ssl_information", {})
        previous_ssl = previous.get("ssl_information", {})

        if current_ssl.get("valid_until") != previous_ssl.get("valid_until"):
            result["ssl_changes"] = {
                "old_expiry": previous_ssl.get("valid_until"),
                "new_expiry": current_ssl.get("valid_until")
            }

        # Technology değişiklikleri
        current_tech = current.get("technology_fingerprint", {})
        previous_tech = previous.get("technology_fingerprint", {})

        if current_tech.get("server") != previous_tech.get("server"):
            result["tech_changes"]["server"] = {
                "old": previous_tech.get("server"),
                "new": current_tech.get("server")
            }

        return result
