import argparse
from rich.console import Console
from modules.dns_lookup import get_dns_records
from modules.whois_lookup import get_whois_info
from modules.ssl_checker import get_ssl_certificate
from modules.port_scanner import scan_ports

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


if __name__ == "__main__":
    main()
