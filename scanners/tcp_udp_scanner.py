"""
TCP/UDP Port Scanner — Uses Scapy SYN scan (root) or socket connect scan (non-root).

No nmap dependency.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn

from models.host import Host
from utils.helpers import is_root, get_service_name, TOP_PORTS_TCP, TOP_PORTS_UDP

logger = logging.getLogger(__name__)


def tcp_udp_scan(
    hosts: dict[str, Host],
    full_scan: bool = False,
    timeout: float = 1.0,
    verbose: bool = False,
) -> None:
    """Scan discovered hosts for open TCP/UDP ports.
    
    Modifies Host objects in-place to add discovered ports.
    Uses Scapy SYN scan if root, otherwise falls back to socket connect scan.
    
    Args:
        hosts: Dictionary of discovered hosts (modified in-place).
        full_scan: If True, scan all 65535 ports. Otherwise top 100.
        timeout: Timeout per port probe.
        verbose: Enable verbose logging.
    """
    if not hosts:
        logger.info("No hosts to port scan.")
        return

    if full_scan:
        tcp_ports = list(range(1, 65536))
        logger.info(f"Full TCP scan (65535 ports) on {len(hosts)} host(s) — this will take a while...")
    else:
        tcp_ports = TOP_PORTS_TCP
        logger.info(f"TCP scan (top {len(tcp_ports)} ports) on {len(hosts)} host(s)")

    udp_ports = TOP_PORTS_UDP

    if is_root():
        _scapy_syn_scan(hosts, tcp_ports, timeout, verbose)
        _scapy_udp_scan(hosts, udp_ports, timeout, verbose)
    else:
        _socket_connect_scan(hosts, tcp_ports, timeout, verbose)
        logger.info("UDP scan requires root — skipping.")


def _scapy_syn_scan(
    hosts: dict[str, Host],
    ports: list[int],
    timeout: float,
    verbose: bool,
) -> None:
    """TCP SYN scan using Scapy (requires root)."""
    try:
        from scapy.all import IP, TCP, sr, conf
        conf.verb = 0
    except ImportError:
        logger.error("Scapy not installed — falling back to socket scan.")
        _socket_connect_scan(hosts, ports, timeout, verbose)
        return

    total_probes = len(hosts) * len(ports)
    logger.info(f"SYN scanning {total_probes} port probes...")

    with Progress(
        TextColumn("[bold cyan]TCP SYN Scan[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(hosts))

        for ip, host in hosts.items():
            try:
                # Build SYN packets for all ports at once
                packets = IP(dst=ip) / TCP(dport=ports, flags="S")
                answered, _ = sr(packets, timeout=timeout, retry=0, verbose=False)

                for sent, received in answered:
                    if received.haslayer(TCP):
                        tcp_layer = received.getlayer(TCP)
                        # SYN-ACK (flags=0x12) means port is open
                        if tcp_layer.flags == 0x12:
                            port = tcp_layer.sport
                            service = get_service_name(port, "tcp")
                            host.add_port(port, "tcp", service, "open")
                            host.add_discovery_method("TCP-SYN")

                            if verbose:
                                logger.info(f"  TCP SYN: {ip}:{port} open ({service})")

            except Exception as e:
                logger.debug(f"SYN scan error for {ip}: {e}")

            progress.update(task, advance=1)


def _scapy_udp_scan(
    hosts: dict[str, Host],
    ports: list[int],
    timeout: float,
    verbose: bool,
) -> None:
    """UDP scan using Scapy (requires root)."""
    try:
        from scapy.all import IP, UDP, ICMP, sr, conf
        conf.verb = 0
    except ImportError:
        return

    logger.info(f"UDP scanning {len(ports)} ports on {len(hosts)} host(s)...")

    with Progress(
        TextColumn("[bold magenta]UDP Scan[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(hosts))

        for ip, host in hosts.items():
            try:
                packets = IP(dst=ip) / UDP(dport=ports)
                answered, unanswered = sr(packets, timeout=timeout, retry=0, verbose=False)

                # For UDP: no response often means open|filtered
                # ICMP port unreachable (type 3, code 3) means closed
                closed_ports = set()
                for sent, received in answered:
                    if received.haslayer(ICMP):
                        icmp_layer = received.getlayer(ICMP)
                        if icmp_layer.type == 3 and icmp_layer.code == 3:
                            closed_ports.add(sent[UDP].dport)

                # Ports that didn't get ICMP unreachable are open|filtered
                for pkt in unanswered:
                    port = pkt[UDP].dport
                    if port not in closed_ports:
                        service = get_service_name(port, "udp")
                        host.add_port(port, "udp", service, "open|filtered")
                        host.add_discovery_method("UDP")

                        if verbose:
                            logger.info(f"  UDP: {ip}:{port} open|filtered ({service})")

            except Exception as e:
                logger.debug(f"UDP scan error for {ip}: {e}")

            progress.update(task, advance=1)


def _socket_connect_scan(
    hosts: dict[str, Host],
    ports: list[int],
    timeout: float,
    verbose: bool,
) -> None:
    """TCP connect scan using sockets (no root required)."""
    total = len(hosts)
    logger.info(f"TCP connect scan ({len(ports)} ports) on {total} host(s)")

    with Progress(
        TextColumn("[bold cyan]TCP Connect Scan[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=total)

        for ip, host in hosts.items():
            open_ports = _scan_host_ports(ip, ports, timeout)
            for port in open_ports:
                service = get_service_name(port, "tcp")
                host.add_port(port, "tcp", service, "open")
                host.add_discovery_method("TCP-connect")

                if verbose:
                    logger.info(f"  TCP: {ip}:{port} open ({service})")

            progress.update(task, advance=1)


def _scan_host_ports(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Scan a single host for open TCP ports using threaded connect scan."""
    open_ports = []

    from typing import Optional

    def check_port(port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except (socket.timeout, OSError):
            pass
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)
