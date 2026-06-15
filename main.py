import argparse
from rich.console import Console
from modules.dns_lookup import get_dns_records
from modules.whois_lookup import get_whois_info
from modules.ssl_checker import get_ssl_certificate
from modules.port_scanner import scan_ports
from modules.subdomain_enum import enumerate_subdomains
from modules.tech_fingerprint import fingerprint_technology
from modules.report_generator import save_report

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="Attack Surface Discovery Toolkit"
    )

    parser.add_argument(
        "--domain",
        required=True,
        help="Target domain"
    )

    args = parser.parse_args()

    console.print(
        f"\n[bold cyan]Scanning:[/bold cyan] {args.domain}\n"
    )

    dns_records = get_dns_records(args.domain)

    for record_type, records in dns_records.items():

        console.print(
            f"\n[bold green]{record_type} Records[/bold green]"
        )

        if records:
            for record in records:
                console.print(f" - {record}")

        else:
            console.print(
                " 🔍 No records found. The attack surface is hiding today")

    whois_info = get_whois_info(args.domain)

    console.print("\n[bold green][+] WHOIS Information[/bold green]\n")

    for key, value in whois_info.items():
        console.print(f"[bold]{key}:[/bold] {value}")

    ssl_info = get_ssl_certificate(args.domain)
    console.print("\n[bold cyan][+] SSL Certificate Information[/bold cyan]\n")
    for key, value in ssl_info.items():
        console.print(f"[bold]{key}:[/bold] {value}")
        open_ports = scan_ports(args.domain)

    console.print(
        "\n[bold cyan][+] Port Scan Results[/bold cyan]\n"
    )

    if open_ports:

        for port in open_ports:
            console.print(
                f"[green]Port {port} is OPEN[/green]"
            )

    else:

        console.print(
            "[red]No open ports discovered[/red]"
        )
    subdomains = enumerate_subdomains(args.domain)

    console.print("\n[bold cyan][+] Subdomain Enumeration[/bold cyan]\n")

    if subdomains:
        for item in subdomains:
            console.print(
                f"[green]{item['subdomain']}[/green] -> {item['ip']}"
            )
    else:
        console.print("🔍 No subdomains found. They are hiding in the shadows.")

    tech_info = fingerprint_technology(args.domain)

    console.print("\n[bold cyan][+] Technology Fingerprinting[/bold cyan]\n")

    for key, value in tech_info.items():
        console.print(f"[bold]{key}:[/bold] {value}")

    report_data = {
        "domain": args.domain,
        "dns_records": dns_records,
        "whois_information": whois_info,
        "ssl_information": ssl_info,
        "open_ports": open_ports,
        "subdomains": subdomains,
        "technology_fingerprint": tech_info
    }

    report_file = save_report(
        args.domain,
        report_data
    )

    console.print(
        f"\n[bold green]Report saved:[/bold green] {report_file}"
    )


if __name__ == "__main__":
    main()
