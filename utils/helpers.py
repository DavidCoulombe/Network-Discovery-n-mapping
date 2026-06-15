"""
Shared utilities for network discovery.
"""

import os
import socket
import ipaddress
from typing import Optional


def is_root() -> bool:
    """Check if the current process has root/admin privileges."""
    return os.geteuid() == 0


def validate_subnet(subnet_str: str) -> Optional[ipaddress.IPv4Network]:
    """Validate and parse a subnet string like '192.168.1.0/24'.
    
    Returns the IPv4Network object or None if invalid.
    """
    try:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        return network
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def get_default_gateway() -> Optional[str]:
    """Attempt to detect the default gateway IP.
    
    Works on macOS and Linux by parsing route table.
    """
    try:
        # macOS / Linux
        import subprocess
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("gateway:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass

    # Fallback: try Linux-style
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        parts = result.stdout.strip().split()
        if "via" in parts:
            idx = parts.index("via")
            return parts[idx + 1]
    except Exception:
        pass

    return None


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """Look up the IANA service name for a port number.
    
    Returns the service name or 'unknown'.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


# Top 100 commonly scanned TCP ports
TOP_PORTS_TCP = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 119,
    135, 139, 143, 161, 162, 179, 389, 443, 445, 465,
    514, 515, 520, 523, 548, 554, 587, 631, 636, 873,
    902, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723,
    1883, 2049, 2082, 2083, 2086, 2087, 2096, 2181, 3306, 3389,
    3690, 4443, 4444, 5000, 5432, 5500, 5601, 5672, 5900, 5901,
    5984, 6379, 6443, 6667, 7001, 7002, 7077, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9000, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 11211, 15672, 25565, 27017, 27018, 28017, 32400, 37777,
    44818, 47808, 49152, 50000, 50070, 54321, 55443, 61616, 62078, 64738,
]

# Common UDP ports worth scanning
TOP_PORTS_UDP = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500,
    514, 520, 1194, 1900, 4500, 5353, 5683, 11211,
]


# Device type display icons for topology diagrams
DEVICE_ICONS = {
    "router": "🔀",
    "switch": "🔗",
    "server": "🖥️",
    "pc": "💻",
    "laptop": "💻",
    "phone": "📱",
    "tv": "📺",
    "printer": "🖨️",
    "game_console": "🎮",
    "iot": "🏠",
    "endpoint": "💻",
    "unknown": "❓",
}

DEVICE_COLORS = {
    "router": "#e74c3c",       # Red
    "switch": "#3498db",       # Blue
    "server": "#2ecc71",       # Green
    "pc": "#9b59b6",           # Purple
    "laptop": "#8e44ad",       # Dark Purple
    "phone": "#1abc9c",        # Turquoise
    "tv": "#f1c40f",           # Yellow
    "printer": "#e67e22",      # Orange
    "game_console": "#d35400", # Dark Orange
    "iot": "#16a085",          # Dark Teal
    "endpoint": "#95a5a6",     # Gray
    "unknown": "#bdc3c7",      # Light Gray
}


def get_arp_cache_macs() -> dict[str, str]:
    """Read the system's ARP table to resolve IP-to-MAC mappings.
    
    Works without root/admin privileges on macOS, Linux, and Windows.
    Returns:
        dict[str, str]: Map of IP address -> MAC address (normalized format).
    """
    import subprocess
    import platform
    import re
    
    arp_map = {}
    system_name = platform.system().lower()
    
    try:
        if system_name == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            # Match Windows arp -a output format (e.g. 192.168.1.1       00-11-22-33-44-55     dynamic)
            pattern = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F\-]{17})")
            for line in result.stdout.splitlines():
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    arp_map[ip] = mac
        else:
            # macOS / Linux
            result = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
            # Match standard BSD/Linux arp -an output format
            # Format: ? (192.168.2.1) at c:ac:8a:e4:2d:22 on en8 ...
            pattern = re.compile(r"\((?P<ip>[0-9\.]+)\)\s+at\s+(?P<mac>[a-fA-F0-9\:]+)")
            for line in result.stdout.splitlines():
                match = pattern.search(line)
                if match:
                    ip = match.group("ip")
                    mac = match.group("mac")
                    
                    # Normalize MAC (add leading zeros if omitted, e.g. f8:17:2d:1b:7:3 -> f8:17:2d:1b:07:03)
                    parts = mac.split(":")
                    if len(parts) == 6:
                        normalized_parts = [p.zfill(2) for p in parts]
                        mac = ":".join(normalized_parts)
                    
                    arp_map[ip] = mac.lower()
                    
    except Exception:
        pass
        
    return arp_map


def get_mac_vendor(mac: str) -> Optional[str]:
    """Look up vendor name from MAC address using Scapy's built-in manufdb."""
    try:
        from scapy.all import conf as scapy_conf
        vendor = scapy_conf.manufdb._resolve_MAC(mac)
        if vendor and vendor != mac:
            return vendor
    except Exception:
        pass
    return None
