import shodan


def get_shodan_info(ip_address: str, api_key: str) -> dict:
    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip_address)

        return {
            "ip": host.get("ip_str"),
            "organization": host.get("org"),
            "isp": host.get("isp"),
            "country": host.get("country_name"),
            "asn": host.get("asn"),
            "ports": host.get("ports"),
            "hostnames": host.get("hostnames"),
        }

    except Exception as e:
        return {
            "error": str(e)
        }
