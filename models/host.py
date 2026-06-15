"""
Host data model for network discovery results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PortInfo:
    """Represents a single discovered open port."""
    port: int
    protocol: str  # "tcp" or "udp"
    service: str = "unknown"
    state: str = "open"

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "state": self.state,
        }


@dataclass
class Host:
    """Represents a discovered network host with all collected information."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: list[PortInfo] = field(default_factory=list)
    snmp_info: dict = field(default_factory=dict)
    discovery_methods: list[str] = field(default_factory=list)
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    # Topology-related fields
    device_type: str = "unknown"  # "router", "switch", "endpoint", "server", "unknown"
    neighbors: list[str] = field(default_factory=list)  # List of neighbor IPs from SNMP/ARP

    def add_discovery_method(self, method: str):
        """Record which protocol discovered this host."""
        if method not in self.discovery_methods:
            self.discovery_methods.append(method)

    def add_port(self, port: int, protocol: str, service: str = "unknown", state: str = "open"):
        """Add a discovered open port, avoiding duplicates."""
        for existing in self.open_ports:
            if existing.port == port and existing.protocol == protocol:
                # Update service name if we got a better one
                if service != "unknown":
                    existing.service = service
                return
        self.open_ports.append(PortInfo(port=port, protocol=protocol, service=service, state=state))

    def infer_device_type(self):
        """Infer device type based on open ports, hostnames, vendors, and SNMP info."""
        port_numbers = {p.port for p in self.open_ports}
        hostname_lower = (self.hostname or "").lower()
        vendor_lower = (self.vendor or "").lower()
        sys_descr = self.snmp_info.get("sysDescr", "").lower()

        # 1. Routers / Gateways / Switches (networking hardware)
        if any(kw in sys_descr for kw in ["router", "cisco ios", "junos", "routeros", "route"]):
            self.device_type = "router"
            return
        if any(kw in sys_descr for kw in ["switch", "catalyst", "procurve"]):
            self.device_type = "switch"
            return
            
        routing_ports = {179, 520, 521, 1985, 2601, 2602}  # BGP, RIP, HSRP, Zebra
        if port_numbers & routing_ports:
            self.device_type = "router"
            return

        # 2. TV / Monitor
        tv_keywords = ["tv", "lgwebostv", "samsungtv", "firetv", "appletv", "bravia", "vizio"]
        if any(kw in hostname_lower for kw in tv_keywords) or any(kw in vendor_lower for kw in ["lg electronics", "samsung"]):
            if any(kw in hostname_lower for kw in tv_keywords):
                self.device_type = "tv"
                return

        # 3. Smartphone / Tablet / Handheld
        phone_keywords = ["phone", "iphone", "pixel", "android", "galaxy", "ipad", "tablet"]
        if any(kw in hostname_lower for kw in phone_keywords) or (any(kw in vendor_lower for kw in ["apple", "google", "samsung"]) and any(kw in hostname_lower for kw in ["phone", "ipad", "pixel", "iphone"])):
            self.device_type = "phone"
            return

        # 4. Printer
        printer_keywords = ["printer", "hp", "canon", "epson", "brother", "xerox", "lexmark"]
        if any(kw in hostname_lower for kw in printer_keywords) or any(kw in vendor_lower for kw in ["hewlett", "canon", "epson", "brother"]):
            self.device_type = "printer"
            return

        # 5. Game Console
        console_keywords = ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch-console"]
        if any(kw in hostname_lower for kw in console_keywords) or any(kw in vendor_lower for kw in ["nintendo", "sony interactive"]):
            self.device_type = "game_console"
            return

        # 6. Smart Home / Speaker / IoT
        iot_keywords = ["nest", "chromecast", "alexa", "echo", "sonos", "speaker", "esp", "arduino", "raspberry", "pi", "iot", "smart"]
        if any(kw in hostname_lower for kw in iot_keywords) or any(kw in vendor_lower for kw in ["espressif", "google", "raspberry pi", "sonos"]):
            self.device_type = "iot"
            return

        # 7. PC / Laptop
        pc_keywords = ["mac", "desktop", "laptop", "pc", "workstation", "book", "computer"]
        if any(kw in hostname_lower for kw in pc_keywords) or "apple" in vendor_lower:
            self.device_type = "laptop" if ("book" in hostname_lower or "laptop" in hostname_lower) else "pc"
            return

        # 8. Server
        server_ports = {3306, 5432, 27017, 1521, 1433, 9200, 6379, 11211}
        if (port_numbers & server_ports) or (22 in port_numbers and 80 in port_numbers and 443 in port_numbers):
            self.device_type = "server"
            return

        # 9. Fallbacks
        if 80 in port_numbers or 443 in port_numbers or 8080 in port_numbers:
            self.device_type = "endpoint"
        elif len(self.neighbors) > 5:
            self.device_type = "switch"
        else:
            self.device_type = "unknown"

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON export."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "device_type": self.device_type,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "snmp_info": self.snmp_info,
            "discovery_methods": self.discovery_methods,
            "neighbors": self.neighbors,
            "last_seen": self.last_seen,
        }

    def __str__(self) -> str:
        parts = [f"{self.ip}"]
        if self.hostname:
            parts.append(f"({self.hostname})")
        if self.mac:
            parts.append(f"[{self.mac}]")
        if self.vendor:
            parts.append(f"- {self.vendor}")
        return " ".join(parts)
