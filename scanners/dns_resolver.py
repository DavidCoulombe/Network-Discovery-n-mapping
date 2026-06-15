"""
DNS Resolver — Forward and reverse DNS lookups for discovered hosts.

Uses Python's socket module for basic lookups and dnspython for detailed queries.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn

from models.host import Host

logger = logging.getLogger(__name__)


def dns_resolve(hosts: dict[str, Host], verbose: bool = False) -> None:
    """Perform reverse DNS lookups on all discovered hosts.
    
    Modifies Host objects in-place to add hostname info.
    
    Args:
        hosts: Dictionary of discovered hosts.
        verbose: Enable verbose logging.
    """
    if not hosts:
        return

    from typing import Tuple, Optional

    def resolve_host(ip: str) -> Tuple[str, Optional[str]]:
        """Reverse DNS lookup for a single IP."""
        hostname = None

        # Method 1: socket.gethostbyaddr (system resolver)
        try:
            result = socket.gethostbyaddr(ip)
            if result and result[0]:
                hostname = result[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        # Method 2: dnspython PTR lookup (if socket failed)
        if not hostname:
            try:
                import dns.resolver
                import dns.reversename

                rev_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(rev_name, "PTR")
                if answers:
                    hostname = str(answers[0]).rstrip(".")
            except Exception:
                pass

        return ip, hostname

    with Progress(
        TextColumn("[bold white]DNS Resolution[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Resolving...", total=len(hosts))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(resolve_host, ip): ip for ip in hosts}

            for future in as_completed(futures):
                ip, hostname = future.result()
                if hostname:
                    hosts[ip].hostname = hostname
                    hosts[ip].add_discovery_method("DNS")

                    if verbose:
                        logger.info(f"  DNS: {ip} -> {hostname}")

                progress.update(task, advance=1)

    resolved = sum(1 for h in hosts.values() if h.hostname)
    logger.info(f"DNS resolution complete: {resolved}/{len(hosts)} resolved")
