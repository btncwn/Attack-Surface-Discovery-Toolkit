# modules/asset_discovery.py
from typing import List, Dict, Union, Set


def compare_discovered_assets(
    standard_subdomains: List[Union[Dict[str, str], str]],
    ct_subdomains: List[str]
) -> Dict[str, Union[List[str], int]]:
    """
    Standart subdomain enumeration ile CT logs'tan gelen subdomain'leri karşılaştırır.

    Args:
        standard_subdomains: Standart enumeration'dan gelen subdomain listesi
        ct_subdomains: CT logs'tan gelen subdomain listesi

    Returns:
        Dict: {
            "hidden_assets": List[str],
            "common_assets": List[str],
            "total_ct_assets": int,
            "total_standard_assets": int
        }
    """
    # Standard subdomain'leri normalize et
    standard_set: Set[str] = set()
    for item in standard_subdomains:
        if isinstance(item, dict):
            sub = item.get('subdomain', '').lower()
            if sub:
                standard_set.add(sub)
        elif isinstance(item, str):
            item = item.lower()
            if item:
                standard_set.add(item)

    # CT subdomain'leri normalize et
    ct_set: Set[str] = set(ct_subdomains)

    # Farkları bul
    hidden_assets = ct_set - standard_set
    common_assets = standard_set & ct_set

    return {
        "hidden_assets": sorted([h for h in hidden_assets if h]),
        "common_assets": sorted([c for c in common_assets if c]),
        "total_ct_assets": len(ct_set),
        "total_standard_assets": len(standard_set)
    }
