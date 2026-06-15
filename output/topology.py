"""
Topology Mapper — Generates network topology diagrams from scan results.

Produces:
  1. A static PNG diagram using matplotlib + networkx
  2. An interactive HTML diagram using PyVis

Topology inference strategy:
  - Identify default gateway as the central node
  - Use SNMP ARP cache and LLDP data for neighbor relationships
  - Group devices by inferred type (router, switch, server, endpoint)
  - Fall back to star topology around gateway when no detailed data is available
"""

import logging
import os
from ipaddress import IPv4Network
from typing import Optional

from models.host import Host
from utils.helpers import get_default_gateway, DEVICE_COLORS

logger = logging.getLogger(__name__)


def generate_topology(
    hosts: dict[str, Host],
    network: IPv4Network,
    output_dir: str,
    gateway_ip: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Generate network topology diagrams.
    
    Args:
        hosts: Dictionary of discovered hosts.
        network: The scanned network.
        output_dir: Output directory path.
        gateway_ip: Known gateway IP (auto-detected if None).
    
    Returns:
        Tuple of (png_path, html_path, drawio_path), elements may be None on failure.
    """
    if not hosts:
        logger.warning("No hosts to map — skipping topology generation.")
        return None, None, None

    try:
        import networkx as nx
    except ImportError:
        logger.error("networkx is not installed. Run: pip install networkx")
        return None, None, None

    os.makedirs(output_dir, exist_ok=True)

    # Detect gateway
    if not gateway_ip:
        gateway_ip = get_default_gateway()
    if gateway_ip:
        logger.info(f"Using gateway: {gateway_ip}")

    # Infer device types for all hosts
    for host in hosts.values():
        host.infer_device_type()

    # If we have a gateway and it's in our scan, mark it as router
    if gateway_ip and gateway_ip in hosts:
        hosts[gateway_ip].device_type = "router"

    # Build the graph
    G = _build_graph(hosts, gateway_ip)

    # Generate outputs
    png_path = _render_png(G, hosts, network, output_dir, gateway_ip)
    html_path = _render_html(G, hosts, network, output_dir, gateway_ip)
    drawio_path = _render_drawio(G, hosts, network, output_dir, gateway_ip)

    return png_path, html_path, drawio_path


def _build_graph(hosts: dict[str, Host], gateway_ip: Optional[str]) -> "nx.Graph":
    """Build a NetworkX graph from discovered hosts and their relationships."""
    import networkx as nx

    G = nx.Graph()

    # Add all hosts as nodes
    for ip, host in hosts.items():
        label = host.hostname if host.hostname else ip
        G.add_node(ip, label=label, device_type=host.device_type, host=host)

    # Add edges based on discovered relationships
    edges_added = set()

    # 1. SNMP ARP cache / neighbor data — real discovered links
    for ip, host in hosts.items():
        for neighbor_ip in host.neighbors:
            if neighbor_ip in hosts and neighbor_ip != ip:
                edge = tuple(sorted([ip, neighbor_ip]))
                if edge not in edges_added:
                    G.add_edge(ip, neighbor_ip, source="snmp_arp")
                    edges_added.add(edge)

    # 2. LLDP neighbor data
    for ip, host in hosts.items():
        lldp = host.snmp_info.get("lldp_neighbors", [])
        for neighbor in lldp:
            n_name = neighbor.get("sysName", "")
            # Try to find this neighbor by hostname
            for other_ip, other_host in hosts.items():
                if other_host.hostname and n_name and n_name in other_host.hostname:
                    edge = tuple(sorted([ip, other_ip]))
                    if edge not in edges_added:
                        G.add_edge(ip, other_ip, source="lldp")
                        edges_added.add(edge)

    # 3. If few edges discovered, fall back to star topology around gateway
    if len(edges_added) < len(hosts) // 2 and gateway_ip and gateway_ip in hosts:
        logger.info("Limited topology data — using star layout around gateway")
        for ip in hosts:
            if ip != gateway_ip:
                edge = tuple(sorted([ip, gateway_ip]))
                if edge not in edges_added:
                    G.add_edge(ip, gateway_ip, source="inferred")
                    edges_added.add(edge)

    # 4. Connect any isolated nodes to gateway (or to nearest node)
    if gateway_ip and gateway_ip in G:
        for node in list(G.nodes()):
            if G.degree(node) == 0 and node != gateway_ip:
                G.add_edge(node, gateway_ip, source="inferred")

    return G


def _render_png(G, hosts, network, output_dir, gateway_ip) -> Optional[str]:
    """Render a static PNG diagram using matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        import networkx as nx
    except ImportError:
        logger.error("matplotlib is not installed — skipping PNG diagram.")
        return None

    filepath = os.path.join(output_dir, f"topology_{str(network).replace('/', '_')}.png")

    fig, ax = plt.subplots(1, 1, figsize=(16, 12))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#1a1a2e")

    # Layout — use spring layout with gateway at center if available
    if gateway_ip and gateway_ip in G:
        pos = nx.spring_layout(G, k=2.5, iterations=50, seed=42, center=(0, 0))
        # Force gateway to center
        pos[gateway_ip] = (0.0, 0.0)
        # Re-run layout with fixed gateway
        fixed = [gateway_ip]
        pos = nx.spring_layout(G, k=2.5, iterations=100, seed=42, pos=pos, fixed=fixed)
    else:
        pos = nx.spring_layout(G, k=2.5, iterations=100, seed=42)

    # Draw edges
    edge_colors = []
    edge_styles = []
    for u, v, data in G.edges(data=True):
        source = data.get("source", "inferred")
        if source == "snmp_arp":
            edge_colors.append("#00d2ff")
            edge_styles.append("solid")
        elif source == "lldp":
            edge_colors.append("#7b2ff7")
            edge_styles.append("solid")
        else:
            edge_colors.append("#444466")
            edge_styles.append("dashed")

    # Draw edges one by one for different styles
    for i, (u, v) in enumerate(G.edges()):
        nx.draw_networkx_edges(
            G, pos, edgelist=[(u, v)],
            edge_color=edge_colors[i],
            style=edge_styles[i],
            alpha=0.6, width=1.5, ax=ax,
        )

    # Draw nodes by device type
    for device_type, color in DEVICE_COLORS.items():
        nodelist = [n for n in G.nodes() if hosts.get(n, Host(ip=n)).device_type == device_type]
        if nodelist:
            sizes = [800 if n == gateway_ip else 500 for n in nodelist]
            nx.draw_networkx_nodes(
                G, pos, nodelist=nodelist,
                node_color=color, node_size=sizes,
                alpha=0.9, edgecolors="#ffffff", linewidths=1.5,
                ax=ax,
            )

    # Labels
    labels = {}
    for node in G.nodes():
        host = hosts.get(node, Host(ip=node))
        if host.hostname:
            # Shorten hostname
            short = host.hostname.split(".")[0]
            labels[node] = f"{short}\n{node}"
        else:
            labels[node] = node

    nx.draw_networkx_labels(
        G, pos, labels, font_size=7,
        font_color="#e0e0e0", font_weight="bold",
        ax=ax,
    )

    # Legend
    legend_patches = [
        mpatches.Patch(color=color, label=dtype.capitalize())
        for dtype, color in DEVICE_COLORS.items()
    ]
    legend_patches.extend([
        mpatches.Patch(color="#00d2ff", label="SNMP/ARP link"),
        mpatches.Patch(color="#7b2ff7", label="LLDP link"),
        mpatches.Patch(color="#444466", label="Inferred link"),
    ])
    ax.legend(
        handles=legend_patches, loc="upper left",
        fontsize=8, facecolor="#16213e", edgecolor="#444466",
        labelcolor="#e0e0e0",
    )

    # Title
    ax.set_title(
        f"Network Topology — {network}",
        fontsize=16, fontweight="bold", color="#e0e0e0", pad=20,
    )
    ax.axis("off")

    plt.tight_layout()
    plt.savefig(filepath, dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
    plt.close()

    logger.info(f"Topology PNG saved to: {filepath}")
    return filepath


def _render_html(G, hosts, network, output_dir, gateway_ip) -> Optional[str]:
    """Render an interactive HTML diagram using PyVis."""
    try:
        from pyvis.network import Network as PyVisNetwork
    except ImportError:
        logger.error("pyvis is not installed — skipping HTML diagram.")
        return None

    filepath = os.path.join(output_dir, f"topology_{str(network).replace('/', '_')}.html")

    net = PyVisNetwork(
        height="900px", width="100%",
        bgcolor="#1a1a2e", font_color="#e0e0e0",
        directed=False,
    )
    net.barnes_hut(gravity=-5000, central_gravity=0.3, spring_length=200)

    # Add nodes
    for ip, host in hosts.items():
        label = host.hostname.split(".")[0] if host.hostname else ip
        color = DEVICE_COLORS.get(host.device_type, "#bdc3c7")

        # Build tooltip with host details
        title_lines = [
            f"<b>{ip}</b>",
            f"Hostname: {host.hostname or 'N/A'}",
            f"MAC: {host.mac or 'N/A'}",
            f"Vendor: {host.vendor or 'N/A'}",
            f"Type: {host.device_type}",
        ]
        if host.open_ports:
            ports_str = ", ".join(f"{p.port}/{p.protocol}" for p in host.open_ports[:15])
            title_lines.append(f"Open Ports: {ports_str}")
        if host.snmp_info.get("sysName"):
            title_lines.append(f"SNMP Name: {host.snmp_info['sysName']}")
        if host.snmp_info.get("sysDescr"):
            descr = host.snmp_info["sysDescr"][:100]
            title_lines.append(f"Description: {descr}")

        title = "<br>".join(title_lines)

        size = 35 if ip == gateway_ip else 20
        border_width = 3 if ip == gateway_ip else 1

        net.add_node(
            ip, label=label, title=title,
            color=color, size=size,
            borderWidth=border_width,
            borderWidthSelected=4,
        )

    # Add edges
    for u, v, data in G.edges(data=True):
        source = data.get("source", "inferred")
        if source == "snmp_arp":
            color = "#00d2ff"
            dashes = False
        elif source == "lldp":
            color = "#7b2ff7"
            dashes = False
        else:
            color = "#444466"
            dashes = True

        net.add_edge(u, v, color=color, dashes=dashes, width=2)

    # Configure physics and interaction
    net.set_options("""
    {
        "physics": {
            "barnesHut": {
                "gravitationalConstant": -5000,
                "centralGravity": 0.3,
                "springLength": 200,
                "springConstant": 0.04
            },
            "stabilization": {
                "iterations": 200
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
        }
    }
    """)

    net.save_graph(filepath)
    logger.info(f"Interactive topology HTML saved to: {filepath}")
    return filepath


def _render_drawio(G, hosts, network, output_dir, gateway_ip) -> Optional[str]:
    """Render a draw.io compatible XML file from the NetworkX graph.
    
    Creates a hierarchical network diagram layout (gateway at top, devices below)
    using standard built-in Network stencil shapes.
    """
    import xml.etree.ElementTree as ET

    filepath = os.path.join(output_dir, f"topology_{str(network).replace('/', '_')}.drawio")

    # Hierarchical layout calculation
    pos = {}
    
    # Separate gateway from other hosts
    other_nodes = [node for node in G.nodes() if node != gateway_ip]
    # Sort other nodes numerically by IP
    other_nodes.sort(key=lambda ip: tuple(int(o) for o in ip.split(".")))
    
    if gateway_ip and gateway_ip in G.nodes():
        pos[gateway_ip] = (400, 100)
    
    # Arrange other nodes in rows of up to 6
    row_size = 6
    spacing_x = 130
    spacing_y = 180
    
    for idx, node in enumerate(other_nodes):
        row = idx // row_size
        col = idx % row_size
        
        # Calculate how many nodes are in this specific row to center them
        remaining_nodes = len(other_nodes) - (row * row_size)
        current_row_size = min(row_size, remaining_nodes)
        
        # Center alignment calculation
        start_x = 400 - ((current_row_size - 1) * spacing_x) / 2
        node_x = start_x + col * spacing_x
        node_y = 300 + row * spacing_y
        
        pos[node] = (int(node_x), int(node_y))
        
    # If no gateway, do simple grid
    if not gateway_ip or gateway_ip not in G.nodes():
        for idx, node in enumerate(other_nodes):
            row = idx // row_size
            col = idx % row_size
            current_row_size = min(row_size, len(other_nodes) - (row * row_size))
            start_x = 400 - ((current_row_size - 1) * spacing_x) / 2
            pos[node] = (int(start_x + col * spacing_x), int(150 + row * spacing_y))

    # Build XML document root structures for Draw.io
    mxfile = ET.Element("mxfile", host="Electron", modified="2026-06-15T00:00:00.000Z", agent="5.0", version="20.0.0")
    diagram = ET.SubElement(mxfile, "diagram", id="page_1", name="Network Topology")
    mxGraphModel = ET.SubElement(
        diagram, "mxGraphModel",
        dx="1200", dy="1000", grid="1", gridSize="10", guides="1",
        tooltips="1", connect="1", arrows="1", fold="1", page="1",
        pageScale="1", pageWidth="827", pageHeight="1169", math="0", shadow="0"
    )
    root = ET.SubElement(mxGraphModel, "root")

    # Base parent/layer nodes
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")

    colors = {
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
        "unknown": "#bdc3c7"       # Light Gray
    }

    # Add vertices (hosts)
    for node in G.nodes():
        host = hosts.get(node, Host(ip=node))
        label_parts = []
        if host.hostname:
            label_parts.append(host.hostname.split(".")[0])
        label_parts.append(node)

        # Open ports snippet
        if host.open_ports:
            ports = ", ".join(str(p.port) for p in host.open_ports[:2])
            if len(host.open_ports) > 2:
                ports += "..."
            label_parts.append(f"Ports: {ports}")

        label = "\n".join(label_parts)
        device_type = host.device_type
        color = colors.get(device_type, "#bdc3c7")

        # Select stencil style and size from mxgraph.networks
        if node == gateway_ip:
            shape = "shape=mxgraph.networks.firewall;"
            width, height = 50, 50
        elif device_type == "router":
            shape = "shape=mxgraph.networks.router;"
            width, height = 50, 50
        elif device_type == "switch":
            shape = "shape=mxgraph.networks.switch;"
            width, height = 50, 40
        elif device_type == "server":
            shape = "shape=mxgraph.networks.server;"
            width, height = 45, 55
        elif device_type == "pc":
            shape = "shape=mxgraph.networks.pc;"
            width, height = 50, 50
        elif device_type == "laptop":
            shape = "shape=mxgraph.networks.laptop;"
            width, height = 50, 45
        elif device_type == "phone":
            shape = "shape=mxgraph.networks.mobile;"
            width, height = 35, 50
        elif device_type == "tv":
            shape = "shape=mxgraph.networks.monitor;"
            width, height = 50, 45
        elif device_type == "printer":
            shape = "shape=mxgraph.networks.printer;"
            width, height = 50, 45
        elif device_type == "game_console":
            shape = "shape=mxgraph.networks.game_console;"
            width, height = 50, 40
        elif device_type == "iot":
            shape = "shape=mxgraph.networks.wireless_hub;"
            width, height = 50, 50
        else:
            shape = "shape=mxgraph.networks.pc;"
            width, height = 50, 50

        # style setting placing labels outside the shape (below it) so the icon is clean
        style = f"{shape}fillColor={color};strokeColor=none;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;pointerEvents=1;dashed=0;outlineConnect=0;"

        # Position nodes centered around (400, 400)
        drawio_x, drawio_y = pos[node]
        drawio_x = int(drawio_x - width / 2)
        drawio_y = int(drawio_y - height / 2)

        mxCell = ET.SubElement(root, "mxCell", id=node, value=label, style=style, vertex="1", parent="1")
        ET.SubElement(mxCell, "mxGeometry", attrib={"x": str(drawio_x), "y": str(drawio_y), "width": str(width), "height": str(height), "as": "geometry"})

    # Add edges (links)
    edge_idx = 1
    for u, v, data in G.edges(data=True):
        edge_id = f"edge_{edge_idx}"
        edge_idx += 1

        source = data.get("source", "inferred")
        if source == "snmp_arp":
            stroke_color = "#00d2ff"
            dashed = "0"
        elif source == "lldp":
            stroke_color = "#7b2ff7"
            dashed = "0"
        else:
            stroke_color = "#444466"
            dashed = "1"

        style = f"endArrow=none;html=1;strokeColor={stroke_color};strokeWidth=2;dashed={dashed};"

        mxCell = ET.SubElement(root, "mxCell", id=edge_id, value="", style=style, edge="1", parent="1", source=u, target=v)
        ET.SubElement(mxCell, "mxGeometry", attrib={"relative": "1", "as": "geometry"})

    # Write binary tree output
    tree = ET.ElementTree(mxfile)
    with open(filepath, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True)

    logger.info(f"Draw.io diagram saved to: {filepath}")
    return filepath
