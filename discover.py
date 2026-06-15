#!/usr/bin/env python3
"""
Network Discovery & Mapping Tool

Scans a given subnet using multiple protocols (ARP, ICMP, TCP/UDP, SNMP, DNS)
to discover hosts and gather detailed information. Produces JSON/CSV reports
and generates network topology diagrams.

Usage:
    sudo python discover.py 192.168.1.0/24
    sudo python discover.py 10.0.0.0/24 --full-scan --csv
    python discover.py 192.168.1.0/24 --no-diagram --verbose

Requires root/sudo for ARP and ICMP scanning (degrades gracefully without it).
"""

import argparse
import logging
import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from models.host import Host
from utils.helpers import validate_subnet, is_root, get_default_gateway, get_arp_cache_macs, get_mac_vendor
from scanners.arp_scanner import arp_scan
from scanners.icmp_scanner import icmp_scan
from scanners.tcp_udp_scanner import tcp_udp_scan
from scanners.snmp_scanner import snmp_scan, SNMPConfig
from scanners.dns_resolver import dns_resolve
from output.json_report import export_json
from output.csv_report import export_csv
from output.topology import generate_topology

console = Console()
logger = logging.getLogger("netdiscovery")


BANNER = """
[bold cyan]
 ╔══════════════════════════════════════════════════════════╗
 ║          🔍  Network Discovery & Mapping Tool           ║
 ║                                                          ║
 ║    ARP • ICMP • TCP/UDP • SNMP • DNS                     ║
 ╚══════════════════════════════════════════════════════════╝
[/]"""


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Discovery & Mapping Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python discover.py 192.168.1.0/24
  sudo python discover.py 10.0.0.0/24 --full-scan --output-dir ./results
  sudo python discover.py 192.168.1.0/24 --no-diagram --csv
        """,
    )
    parser.add_argument(
        "subnet",
        nargs="?",
        help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./results",
        help="Output directory for reports (default: ./results)",
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Scan all 65535 TCP ports (default: top 100 only)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float, default=2.0,
        help="Per-host timeout in seconds (default: 2)",
    )
    parser.add_argument(
        "--no-diagram",
        action="store_true",
        help="Skip topology diagram generation",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Also export CSV report alongside JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def setup_logging(verbose: bool):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Suppress noisy loggers
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)


def print_summary_table(hosts: dict[str, Host]):
    """Print a rich summary table of discovered hosts."""
    if not hosts:
        console.print("\n[bold red]No hosts discovered.[/]")
        return

    table = Table(
        title="Discovered Hosts",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on #16213e",
        title_style="bold cyan",
        show_lines=True,
    )

    table.add_column("IP Address", style="bold white", min_width=15)
    table.add_column("Hostname", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Vendor", style="magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Open Ports", style="white", max_width=35)
    table.add_column("Methods", style="dim")

    # Sort by IP
    sorted_hosts = sorted(hosts.items(), key=lambda x: tuple(int(o) for o in x[0].split(".")))

    for ip, host in sorted_hosts:
        ports_str = ", ".join(
            f"{p.port}/{p.protocol}" for p in host.open_ports[:8]
        )
        if len(host.open_ports) > 8:
            ports_str += f" (+{len(host.open_ports) - 8} more)"

        methods = ", ".join(host.discovery_methods)

        table.add_row(
            ip,
            host.hostname or "—",
            host.mac or "—",
            host.vendor or "—",
            host.device_type,
            ports_str or "—",
            methods,
        )

    console.print()
    console.print(table)


def merge_hosts(base: dict[str, Host], new: dict[str, Host]) -> dict[str, Host]:
    """Merge two host dictionaries, combining data from both."""
    for ip, new_host in new.items():
        if ip in base:
            existing = base[ip]
            # Merge MAC if missing
            if not existing.mac and new_host.mac:
                existing.mac = new_host.mac
            if not existing.vendor and new_host.vendor:
                existing.vendor = new_host.vendor
            # Merge discovery methods
            for method in new_host.discovery_methods:
                existing.add_discovery_method(method)
        else:
            base[ip] = new_host
    return base


def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    console.print(BANNER)

    # Privilege check
    if is_root():
        console.print("[bold green]✓ Running with root privileges[/] — full scanning enabled.\n")
    else:
        console.print("[bold yellow]⚠ Running without root[/] — ARP/ICMP/SYN scans will be limited.\n")

    # Get subnet (from args or prompt)
    subnet_str = args.subnet
    if not subnet_str:
        subnet_str = input("[?] Enter target subnet (e.g., 192.168.1.0/24): ").strip()

    network = validate_subnet(subnet_str)
    if not network:
        console.print(f"[bold red]✗ Invalid subnet: '{subnet_str}'[/]")
        console.print("  Use CIDR notation, e.g., 192.168.1.0/24")
        sys.exit(1)

    host_count = network.num_addresses - 2  # Exclude network and broadcast
    console.print(f"[bold]Target:[/] {network}  ({host_count} hosts)")

    # Detect gateway
    gateway_ip = get_default_gateway()
    if gateway_ip:
        console.print(f"[bold]Gateway:[/] {gateway_ip}")

    # SNMP configuration prompt
    snmp_config = SNMPConfig.from_prompt()

    console.print()
    console.print(Panel(
        "[bold]Starting network discovery...[/]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    start_time = time.time()
    all_hosts: dict[str, Host] = {}

    # ─── Phase 1: Host Discovery ───────────────────────────────────
    console.print("[bold underline]Phase 1: Host Discovery[/]\n")

    # ARP Scan (Layer 2 — local subnet only, requires root)
    arp_hosts = arp_scan(network, timeout=args.timeout, verbose=args.verbose)
    all_hosts = merge_hosts(all_hosts, arp_hosts)
    console.print(f"  ARP:  [green]{len(arp_hosts)}[/] host(s) found")

    # ICMP Ping Sweep
    icmp_hosts = icmp_scan(network, timeout=args.timeout, verbose=args.verbose)
    new_from_icmp = len([ip for ip in icmp_hosts if ip not in all_hosts])
    all_hosts = merge_hosts(all_hosts, icmp_hosts)
    console.print(f"  ICMP: [green]{len(icmp_hosts)}[/] host(s) responded ({new_from_icmp} new)")

    # Retrieve MAC addresses from system's ARP cache (especially useful when running without root)
    arp_cache = get_arp_cache_macs()
    resolved_macs = 0
    resolved_vendors = 0
    
    for ip, host in all_hosts.items():
        if not host.mac and ip in arp_cache:
            host.mac = arp_cache[ip]
            resolved_macs += 1
            
        if host.mac and not host.vendor:
            vendor = get_mac_vendor(host.mac)
            if vendor:
                host.vendor = vendor
                resolved_vendors += 1
                
    if resolved_macs > 0 or resolved_vendors > 0:
        console.print(f"  ARP Cache: resolved [green]{resolved_macs}[/] MACs and [green]{resolved_vendors}[/] vendors from cache")

    if not all_hosts:
        console.print("[bold red]No hosts discovered. Check your subnet and permissions.[/]")
        sys.exit(0)

    # ─── Phase 2: Deep Scanning ────────────────────────────────────
    console.print("[bold underline]Phase 2: Deep Scanning[/]\n")

    # DNS Resolution
    dns_resolve(all_hosts, verbose=args.verbose)
    resolved = sum(1 for h in all_hosts.values() if h.hostname)
    console.print(f"  DNS:  [green]{resolved}[/] hostname(s) resolved")

    # TCP/UDP Port Scan
    tcp_udp_scan(all_hosts, full_scan=args.full_scan, timeout=args.timeout, verbose=args.verbose)
    with_ports = sum(1 for h in all_hosts.values() if h.open_ports)
    total_ports = sum(len(h.open_ports) for h in all_hosts.values())
    console.print(f"  Ports: [green]{total_ports}[/] open ports across {with_ports} host(s)")

    # SNMP Scan
    snmp_scan(all_hosts, snmp_config, timeout=args.timeout, verbose=args.verbose)
    with_snmp = sum(1 for h in all_hosts.values() if h.snmp_info)
    console.print(f"  SNMP: [green]{with_snmp}[/] host(s) responded")

    # Infer device types
    for host in all_hosts.values():
        host.infer_device_type()

    scan_duration = time.time() - start_time

    # ─── Phase 3: Results ──────────────────────────────────────────
    console.print(f"\n[bold underline]Phase 3: Results[/]\n")

    # Print summary table
    print_summary_table(all_hosts)

    # Export JSON
    scan_options = {
        "full_scan": args.full_scan,
        "timeout": args.timeout,
        "snmp_version": snmp_config.version if snmp_config.enabled else "disabled",
        "is_root": is_root(),
    }
    json_path = export_json(all_hosts, network, args.output_dir, scan_duration, scan_options)
    console.print(f"\n  📄 JSON: [link=file://{json_path}]{json_path}[/link]")

    # Export CSV (if requested)
    if args.csv:
        csv_path = export_csv(all_hosts, network, args.output_dir)
        console.print(f"  📊 CSV:  [link=file://{csv_path}]{csv_path}[/link]")

    # ─── Phase 4: Topology Diagram ─────────────────────────────────
    if not args.no_diagram:
        console.print(f"\n[bold underline]Phase 4: Topology Mapping[/]\n")
        png_path, html_path, drawio_path = generate_topology(all_hosts, network, args.output_dir, gateway_ip)
        if png_path:
            console.print(f"  🗺️  PNG:  [link=file://{png_path}]{png_path}[/link]")
        if html_path:
            console.print(f"  🌐 HTML: [link=file://{html_path}]{html_path}[/link]")
            console.print("       [dim]Open the HTML file in a browser for interactive topology.[/dim]")
        if drawio_path:
            console.print(f"  ✏️  Draw.io: [link=file://{drawio_path}]{drawio_path}[/link]")
            console.print("       [dim]Import this file directly into draw.io / diagrams.net to edit.[/dim]")

    # ─── Done ──────────────────────────────────────────────────────
    console.print(f"\n[bold green]✓ Scan complete![/] Duration: {scan_duration:.1f}s | Hosts: {len(all_hosts)}")
    console.print()


if __name__ == "__main__":
    main()
