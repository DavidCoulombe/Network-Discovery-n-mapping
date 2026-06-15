"""
SNMP Scanner — Query SNMP-enabled devices for system info and neighbor data.

Supports SNMPv1 and SNMPv2c. Queries standard MIBs for device info,
interface tables, and ARP caches (critical for topology mapping).
"""

import logging
from typing import Optional

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn

from models.host import Host

logger = logging.getLogger(__name__)

# Standard OIDs for system info (SNMPv2-MIB)
SYSTEM_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
}

# OID prefixes for table walks
IF_TABLE_OID = "1.3.6.1.2.1.2.2.1"            # ifTable — interface info
ARP_TABLE_OID = "1.3.6.1.2.1.4.22.1"           # ipNetToMediaTable — ARP cache
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"           # ifDescr
IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"     # ifOperStatus
ARP_PHYS_ADDR_OID = "1.3.6.1.2.1.4.22.1.2"     # ipNetToMediaPhysAddress (MAC)
ARP_NET_ADDR_OID = "1.3.6.1.2.1.4.22.1.3"      # ipNetToMediaNetAddress (IP)

# LLDP neighbor OIDs
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"   # lldpRemSysName
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"   # lldpRemPortDesc
LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.4"   # lldpRemManAddrIfId


class SNMPConfig:
    """SNMP configuration from user prompts."""

    def __init__(self, version: str = "1", community: str = "public", enabled: bool = True):
        self.version = version  # "1" or "2c"
        self.community = community
        self.enabled = enabled

    @classmethod
    def from_prompt(cls) -> "SNMPConfig":
        """Interactively prompt the user for SNMP settings."""
        from rich.console import Console
        console = Console()

        console.print("\n[bold yellow]── SNMP Configuration ──[/]")

        skip = input("[?] Skip SNMP scanning? (y/N): ").strip().lower()
        if skip == "y":
            console.print("  [dim]SNMP scanning disabled.[/dim]")
            return cls(enabled=False)

        version = input("[?] SNMP Version (1/2c) [1]: ").strip() or "1"
        if version not in ("1", "2c"):
            console.print(f"  [yellow]Invalid version '{version}', defaulting to 1[/yellow]")
            version = "1"

        community = input("[?] SNMP Community String [public]: ").strip() or "public"

        console.print(f"  [dim]Using SNMPv{version} with community '{community}'[/dim]")
        return cls(version=version, community=community, enabled=True)

    @property
    def mp_model(self) -> int:
        """Return pysnmp mpModel value: 0 for v1, 1 for v2c."""
        return 0 if self.version == "1" else 1


def snmp_scan(
    hosts: dict[str, Host],
    snmp_config: SNMPConfig,
    timeout: float = 2.0,
    verbose: bool = False,
) -> None:
    """Probe discovered hosts for SNMP information.
    
    Modifies Host objects in-place.
    
    Args:
        hosts: Dictionary of discovered hosts.
        snmp_config: SNMP configuration from user prompt.
        timeout: SNMP request timeout.
        verbose: Enable verbose logging.
    """
    if not snmp_config.enabled:
        logger.info("SNMP scanning disabled by user.")
        return

    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
            getCmd, nextCmd,
        )
    except ImportError:
        logger.error("pysnmp is not installed. Run: pip install pysnmp")
        return

    if not hosts:
        return

    logger.info(f"Starting SNMP scan (v{snmp_config.version}) on {len(hosts)} host(s)")

    engine = SnmpEngine()
    community = CommunityData(snmp_config.community, mpModel=snmp_config.mp_model)

    with Progress(
        TextColumn("[bold yellow]SNMP Scan[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("hosts"),
        transient=True,
    ) as progress:
        task = progress.add_task("Querying...", total=len(hosts))

        for ip, host in hosts.items():
            try:
                target = UdpTransportTarget((ip, 161), timeout=timeout, retries=1)

                # 1. Get system info
                sys_info = _get_system_info(engine, community, target)
                if sys_info:
                    host.snmp_info.update(sys_info)
                    host.add_discovery_method("SNMP")

                    if verbose:
                        name = sys_info.get("sysName", "")
                        logger.info(f"  SNMP: {ip} — sysName={name}")

                    # 2. Get interface info
                    interfaces = _get_interfaces(engine, community, target)
                    if interfaces:
                        host.snmp_info["interfaces"] = interfaces

                    # 3. Get ARP cache (for topology mapping)
                    arp_neighbors = _get_arp_cache(engine, community, target)
                    if arp_neighbors:
                        host.snmp_info["arp_cache"] = arp_neighbors
                        # Add neighbor IPs for topology
                        host.neighbors.extend([n["ip"] for n in arp_neighbors if n.get("ip")])

                    # 4. Try LLDP neighbors
                    lldp_neighbors = _get_lldp_neighbors(engine, community, target)
                    if lldp_neighbors:
                        host.snmp_info["lldp_neighbors"] = lldp_neighbors

            except Exception as e:
                logger.debug(f"SNMP error for {ip}: {e}")

            progress.update(task, advance=1)

    snmp_count = sum(1 for h in hosts.values() if "SNMP" in h.discovery_methods)
    logger.info(f"SNMP scan complete: {snmp_count} host(s) responded to SNMP")


def _get_system_info(engine, community, target) -> Optional[dict]:
    """Query standard system MIB OIDs."""
    from pysnmp.hlapi import getCmd, ObjectType, ObjectIdentity, ContextData

    oids = [ObjectType(ObjectIdentity(oid)) for oid in SYSTEM_OIDS.values()]
    oid_names = list(SYSTEM_OIDS.keys())

    error_indication, error_status, error_index, var_binds = next(
        getCmd(engine, community, target, ContextData(), *oids)
    )

    if error_indication or error_status:
        return None

    result = {}
    for i, var_bind in enumerate(var_binds):
        name = oid_names[i] if i < len(oid_names) else str(var_bind[0])
        value = str(var_bind[1])
        if value and value != "":
            result[name] = value

    return result if result else None


def _get_interfaces(engine, community, target) -> list[dict]:
    """Walk ifTable to get interface descriptions and status."""
    from pysnmp.hlapi import nextCmd, ObjectType, ObjectIdentity, ContextData

    interfaces = []

    try:
        # Walk ifDescr
        descr_map = {}
        for error_indication, error_status, error_index, var_binds in nextCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(IF_DESCR_OID)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                oid = str(var_bind[0])
                idx = oid.split(".")[-1]
                descr_map[idx] = str(var_bind[1])

        # Walk ifOperStatus
        status_map = {}
        for error_indication, error_status, error_index, var_binds in nextCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(IF_OPER_STATUS_OID)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                oid = str(var_bind[0])
                idx = oid.split(".")[-1]
                status_val = int(var_bind[1])
                status_map[idx] = "up" if status_val == 1 else "down"

        # Merge
        for idx, descr in descr_map.items():
            interfaces.append({
                "index": idx,
                "description": descr,
                "status": status_map.get(idx, "unknown"),
            })

    except Exception as e:
        logger.debug(f"Interface walk error: {e}")

    return interfaces


def _get_arp_cache(engine, community, target) -> list[dict]:
    """Walk ipNetToMediaTable to get ARP cache entries."""
    from pysnmp.hlapi import nextCmd, ObjectType, ObjectIdentity, ContextData

    arp_entries = []

    try:
        for error_indication, error_status, error_index, var_binds in nextCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(ARP_NET_ADDR_OID)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                ip_val = str(var_bind[1])
                if ip_val:
                    arp_entries.append({"ip": ip_val})

    except Exception as e:
        logger.debug(f"ARP cache walk error: {e}")

    return arp_entries


def _get_lldp_neighbors(engine, community, target) -> list[dict]:
    """Try to get LLDP neighbor information."""
    from pysnmp.hlapi import nextCmd, ObjectType, ObjectIdentity, ContextData

    neighbors = []

    try:
        for error_indication, error_status, error_index, var_binds in nextCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(LLDP_REM_SYS_NAME)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                name = str(var_bind[1])
                if name:
                    neighbors.append({"sysName": name})

    except Exception as e:
        logger.debug(f"LLDP walk error: {e}")

    return neighbors
