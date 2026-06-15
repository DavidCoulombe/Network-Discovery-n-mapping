"""
ARP Scanner — Layer 2 discovery for local subnet.

Uses Scapy to send ARP requests to the broadcast address.
Requires root privileges.
"""

import logging
from ipaddress import IPv4Network
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn

from models.host import Host
from utils.helpers import is_root

logger = logging.getLogger(__name__)


def arp_scan(network: IPv4Network, timeout: float = 2.0, verbose: bool = False) -> dict[str, Host]:
    """Perform ARP scan on the given network.
    
    Args:
        network: The IPv4 network to scan.
        timeout: Timeout in seconds for ARP responses.
        verbose: Enable verbose logging.
    
    Returns:
        Dictionary mapping IP addresses to Host objects.
    """
    if not is_root():
        logger.warning("ARP scan requires root privileges — skipping.")
        return {}

    try:
        # Import scapy here to avoid issues if not installed
        from scapy.all import ARP, Ether, srp, conf
        # Suppress Scapy's own verbose output
        conf.verb = 0
    except ImportError:
        logger.error("Scapy is not installed. Run: pip install scapy")
        return {}

    hosts: dict[str, Host] = {}
    target = str(network)

    logger.info(f"Starting ARP scan on {target}")

    try:
        # Build ARP request packet
        # Ether(dst="ff:ff:ff:ff:ff:ff") — broadcast at L2
        # ARP(pdst=target) — who has this IP?
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]ARP Scan[/] — scanning {task.description}..."),
            transient=True,
        ) as progress:
            progress.add_task(description=target, total=None)
            answered, _ = srp(arp_request, timeout=timeout, retry=1, verbose=False)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc

            host = Host(ip=ip, mac=mac)
            host.add_discovery_method("ARP")

            # Try to get vendor from Scapy's manufacturer database
            try:
                from scapy.all import conf as scapy_conf
                vendor = scapy_conf.manufdb._resolve_MAC(mac)
                if vendor and vendor != mac:
                    host.vendor = vendor
            except Exception:
                pass

            hosts[ip] = host

            if verbose:
                logger.info(f"  ARP: {ip} -> {mac}" + (f" ({host.vendor})" if host.vendor else ""))

        logger.info(f"ARP scan complete: {len(hosts)} host(s) found")

    except PermissionError:
        logger.warning("ARP scan failed: insufficient permissions.")
    except Exception as e:
        logger.error(f"ARP scan error: {e}")

    return hosts
