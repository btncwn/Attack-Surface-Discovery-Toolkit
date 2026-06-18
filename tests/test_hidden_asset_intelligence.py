from modules.hidden_asset_intelligence import HiddenAssetIntelligence

domain = "blackbullbarbers.co.uk"

ct_subdomains = [
    "blackbullbarbers.co.uk",
    "email.blackbullbarbers.co.uk",
    "www.blackbullbarbers.co.uk",
    "www.email.blackbullbarbers.co.uk"
]

standard_subdomains = [
    "www.blackbullbarbers.co.uk",
    "autodiscover.blackbullbarbers.co.uk"
]

result = HiddenAssetIntelligence.analyze(
    domain,
    ct_subdomains,
    standard_subdomains
)

print(result)
