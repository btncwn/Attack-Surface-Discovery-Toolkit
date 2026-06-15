import whois


def get_whois_info(domain: str) -> dict:
    try:
        data = whois.whois(domain)

        return {
            "domain_name": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }

    except Exception:
        return {
            "domain_name": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
        }
