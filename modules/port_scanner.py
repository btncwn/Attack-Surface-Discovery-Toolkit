import socket
import threading


def scan_single_port(domain, port, open_ports):

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (domain, port)
        )

        if result == 0:
            open_ports.append(port)

        sock.close()

    except Exception:
        pass


def scan_ports(domain: str) -> list:

    common_ports = [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        3306,
        3389,
        8080,
        8443
    ]

    open_ports = []

    threads = []

    for port in common_ports:

        thread = threading.Thread(
            target=scan_single_port,
            args=(domain, port, open_ports)
        )

        threads.append(thread)

        thread.start()

    for thread in threads:
        thread.join()

    return sorted(open_ports)
