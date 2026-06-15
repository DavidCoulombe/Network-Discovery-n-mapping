"""
CSV Report — Flattened tabular export of scan results.

One row per host, ports and methods comma-separated.
"""

import csv
import logging
import os
from datetime import datetime
from ipaddress import IPv4Network

from models.host import Host

logger = logging.getLogger(__name__)


def export_csv(
    hosts: dict[str, Host],
    network: IPv4Network,
    output_dir: str,
) -> str:
    """Export scan results to a CSV file.
    
    Args:
        hosts: Dictionary of discovered hosts.
        network: The scanned network.
        output_dir: Output directory path.
    
    Returns:
        Path to the generated CSV file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    subnet_safe = str(network).replace("/", "_").replace(".", "-")
    filename = f"scan_{subnet_safe}_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    fieldnames = [
        "ip",
        "hostname",
        "mac",
        "vendor",
        "device_type",
        "open_tcp_ports",
        "open_udp_ports",
        "snmp_sysName",
        "snmp_sysDescr",
        "snmp_sysLocation",
        "snmp_sysContact",
        "snmp_sysUpTime",
        "discovery_methods",
        "neighbor_count",
        "last_seen",
    ]

    # Sort hosts by IP numerically
    sorted_hosts = sorted(hosts.items(), key=lambda x: tuple(int(o) for o in x[0].split(".")))

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for ip, host in sorted_hosts:
            tcp_ports = ", ".join(
                f"{p.port}/{p.service}" for p in host.open_ports if p.protocol == "tcp"
            )
            udp_ports = ", ".join(
                f"{p.port}/{p.service}" for p in host.open_ports if p.protocol == "udp"
            )

            row = {
                "ip": host.ip,
                "hostname": host.hostname or "",
                "mac": host.mac or "",
                "vendor": host.vendor or "",
                "device_type": host.device_type,
                "open_tcp_ports": tcp_ports,
                "open_udp_ports": udp_ports,
                "snmp_sysName": host.snmp_info.get("sysName", ""),
                "snmp_sysDescr": host.snmp_info.get("sysDescr", ""),
                "snmp_sysLocation": host.snmp_info.get("sysLocation", ""),
                "snmp_sysContact": host.snmp_info.get("sysContact", ""),
                "snmp_sysUpTime": host.snmp_info.get("sysUpTime", ""),
                "discovery_methods": ", ".join(host.discovery_methods),
                "neighbor_count": len(host.neighbors),
                "last_seen": host.last_seen,
            }
            writer.writerow(row)

    logger.info(f"CSV report saved to: {filepath}")
    return filepath
