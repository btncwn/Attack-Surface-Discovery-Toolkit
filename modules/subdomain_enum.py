import dns.resolver


def enumerate_subdomains(domain: str) -> list:
    common_subdomains = [
        "www",
        "mail",
        "webmail",
        "admin",
        "portal",
        "dev",
        "test",
        "staging",
        "api",
        "shop",
        "blog",
        "autodiscover"
    ]

    discovered_subdomains = []

    for subdomain in common_subdomains:
        full_domain = f"{subdomain}.{domain}"

        try:
            answers = dns.resolver.resolve(full_domain, "A")

            for answer in answers:
                discovered_subdomains.append(
                    {
                        "subdomain": full_domain,
                        "ip": str(answer)
                    }
                )

        except Exception:
            pass

    return discovered_subdomains
