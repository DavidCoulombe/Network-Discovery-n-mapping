"""
JSON Report — Primary output format for scan results.

Produces a structured JSON file with full host details and scan metadata.
"""

import json
import logging
import os
from datetime import datetime
from ipaddress import IPv4Network

from models.host import Host

logger = logging.getLogger(__name__)


def export_json(
    hosts: dict[str, Host],
    network: IPv4Network,
    output_dir: str,
    scan_duration: float,
    scan_options: dict,
) -> str:
    """Export scan results to a JSON file.
    
    Args:
        hosts: Dictionary of discovered hosts.
        network: The scanned network.
        output_dir: Output directory path.
        scan_duration: Total scan duration in seconds.
        scan_options: Scan configuration options.
    
    Returns:
        Path to the generated JSON file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    subnet_safe = str(network).replace("/", "_").replace(".", "-")
    filename = f"scan_{subnet_safe}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    report = {
        "scan_metadata": {
            "subnet": str(network),
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(scan_duration, 2),
            "total_hosts_found": len(hosts),
            "options": scan_options,
        },
        "hosts": {
            ip: host.to_dict() for ip, host in sorted(hosts.items(), key=_ip_sort_key)
        },
        "summary": {
            "total_hosts": len(hosts),
            "with_hostname": sum(1 for h in hosts.values() if h.hostname),
            "with_open_ports": sum(1 for h in hosts.values() if h.open_ports),
            "with_snmp": sum(1 for h in hosts.values() if h.snmp_info),
            "device_types": _count_device_types(hosts),
            "discovery_methods": _count_methods(hosts),
        },
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"JSON report saved to: {filepath}")
    return filepath


def _ip_sort_key(item: tuple) -> tuple:
    """Sort key for IP addresses (numeric ordering)."""
    ip = item[0]
    return tuple(int(octet) for octet in ip.split("."))


def _count_device_types(hosts: dict[str, Host]) -> dict:
    """Count hosts by device type."""
    counts: dict[str, int] = {}
    for host in hosts.values():
        dt = host.device_type
        counts[dt] = counts.get(dt, 0) + 1
    return counts


def _count_methods(hosts: dict[str, Host]) -> dict:
    """Count discovery methods used."""
    counts: dict[str, int] = {}
    for host in hosts.values():
        for method in host.discovery_methods:
            counts[method] = counts.get(method, 0) + 1
    return counts
