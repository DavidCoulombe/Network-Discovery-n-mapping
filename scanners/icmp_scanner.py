"""
ICMP Scanner — Ping sweep for host discovery.

Uses Scapy ICMP echo requests. Requires root for raw sockets.
Falls back to TCP connect on ports 80/443 if not root.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn

from models.host import Host
from utils.helpers import is_root

logger = logging.getLogger(__name__)


import platform
import subprocess

def _ping_host(ip: str, timeout: float) -> bool:
    """Ping a host using the OS native ping command.
    
    Returns True if the host responds, False otherwise.
    """
    system_name = platform.system().lower()
    
    # Configure ping arguments depending on OS
    if system_name == "windows":
        timeout_ms = max(50, int(timeout * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system_name == "darwin":
        # macOS: -W is in milliseconds
        timeout_ms = max(50, int(timeout * 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        # Linux / Unix: -W is in seconds
        timeout_sec = max(1, int(timeout))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _system_ping_sweep(hosts_list: list[str], timeout: float, verbose: bool) -> dict[str, Host]:
    """Perform ping sweep using the system's native ping command.
    
    No root privileges required.
    """
    hosts: dict[str, Host] = {}
    
    logger.info(f"Starting OS native ping sweep on {len(hosts_list)} hosts")

    def probe_host(ip: str) -> tuple[str, bool]:
        alive = _ping_host(ip, timeout)
        return ip, alive

    with Progress(
        TextColumn("[bold green]OS Ping Sweep[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Pinging...", total=len(hosts_list))

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(probe_host, ip): ip for ip in hosts_list}
            for future in as_completed(futures):
                ip, alive = future.result()
                if alive:
                    host = Host(ip=ip)
                    host.add_discovery_method("Ping")
                    hosts[ip] = host
                    if verbose:
                        logger.info(f"  Ping: {ip} is alive")
                progress.update(task, advance=1)

    logger.info(f"OS ping sweep complete: {len(hosts)} host(s) responded")
    return hosts


def icmp_scan(network: IPv4Network, timeout: float = 2.0, verbose: bool = False) -> dict[str, Host]:
    """Perform ICMP ping sweep on the given network.
    
    Falls back to OS ping sweep and TCP connect probes if not root.
    
    Args:
        network: The IPv4 network to scan.
        timeout: Timeout in seconds per probe.
        verbose: Enable verbose logging.
    
    Returns:
        Dictionary mapping IP addresses to Host objects.
    """
    hosts_list = [str(ip) for ip in network.hosts()]

    if is_root():
        return _scapy_icmp_scan(hosts_list, timeout, verbose)
    else:
        logger.warning("No root privileges — using OS native ping sweep and TCP connect probes.")
        discovered = _system_ping_sweep(hosts_list, timeout, verbose)
        tcp_discovered = _tcp_connect_probe(hosts_list, timeout, verbose)
        
        # Merge TCP results into discovered
        for ip, host in tcp_discovered.items():
            if ip in discovered:
                discovered[ip].add_discovery_method("TCP-probe")
            else:
                discovered[ip] = host
                
        return discovered


def _scapy_icmp_scan(hosts_list: list[str], timeout: float, verbose: bool) -> dict[str, Host]:
    """ICMP ping sweep using Scapy (requires root)."""
    try:
        from scapy.all import IP, ICMP, sr, conf
        conf.verb = 0
    except ImportError:
        logger.error("Scapy is not installed. Run: pip install scapy")
        return {}

    hosts: dict[str, Host] = {}

    logger.info(f"Starting ICMP ping sweep on {len(hosts_list)} hosts")

    try:
        # Build ICMP packets for all hosts
        # Send them in a single batch for speed
        packets = [IP(dst=ip) / ICMP() for ip in hosts_list]

        with Progress(
            TextColumn("[bold green]ICMP Scan[/]"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("hosts"),
            transient=True,
        ) as progress:
            task = progress.add_task("Pinging...", total=len(hosts_list))

            # sr() sends and receives — we use a batch approach
            answered, _ = sr(packets, timeout=timeout, retry=0, verbose=False)
            progress.update(task, completed=len(hosts_list))

        for sent, received in answered:
            # ICMP echo reply (type 0) means host is alive
            if received.haslayer(ICMP):
                icmp_layer = received.getlayer(ICMP)
                if icmp_layer.type == 0:  # Echo reply
                    ip = received.src
                    host = Host(ip=ip)
                    host.add_discovery_method("ICMP")
                    hosts[ip] = host

                    if verbose:
                        logger.info(f"  ICMP: {ip} is alive")

        logger.info(f"ICMP scan complete: {len(hosts)} host(s) responded")

    except Exception as e:
        logger.error(f"ICMP scan error: {e}")

    return hosts


def _tcp_connect_probe(hosts_list: list[str], timeout: float, verbose: bool) -> dict[str, Host]:
    """TCP connect probe fallback when we don't have root."""
    hosts: dict[str, Host] = {}
    probe_ports = [80, 443, 22]

    logger.info(f"Starting TCP connect probe on {len(hosts_list)} hosts (ports {probe_ports})")

    def probe_host(ip: str) -> tuple[str, bool]:
        for port in probe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return ip, True
            except (socket.timeout, OSError):
                continue
        return ip, False

    with Progress(
        TextColumn("[bold green]TCP Probe[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Probing...", total=len(hosts_list))

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(probe_host, ip): ip for ip in hosts_list}
            for future in as_completed(futures):
                ip, alive = future.result()
                if alive:
                    host = Host(ip=ip)
                    host.add_discovery_method("TCP-probe")
                    hosts[ip] = host
                    if verbose:
                        logger.info(f"  TCP: {ip} is alive")
                progress.update(task, advance=1)

    logger.info(f"TCP probe complete: {len(hosts)} host(s) responded")
    return hosts
