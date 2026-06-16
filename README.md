# 🔍 Network Discovery & Mapping Tool

A Python-based network discovery tool that scans subnets using multiple protocols and generates network topology diagrams for Draw.io.

Made using AI by "VibeCodding". Work in progress.

## Features

- **Multi-protocol scanning**: ARP, ICMP, TCP/UDP, SNMP, DNS
- **Zero external binary dependencies**: Uses Scapy for all packet operations (no nmap needed)
- **Interactive SNMP configuration**: Prompts for version (v1/v2c) and community string
- **Rich terminal output**: Progress bars, colored tables, and status updates
- **Dual output formats**: JSON (primary) + optional CSV
- **Network topology diagrams**: Static PNG + interactive HTML (drag, zoom, hover)
- **Graceful degradation**: Works without root (limited scanning) and handles missing dependencies

## Requirements

- Python 3.10+
- Root/sudo for full scanning (ARP, ICMP, SYN scan)

## Installation

```bash
# Clone or navigate to the project
cd Network-Discovery-n-mapping

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic scan
```bash
sudo .venv/bin/python discover.py 192.168.1.0/24
```

### Full scan with CSV export
```bash
sudo .venv/bin/python discover.py 10.0.0.0/24 --full-scan --csv
```

### Without root (limited but functional)
```bash
python discover.py 192.168.1.0/24
```

### All options
```
Usage: sudo python discover.py <subnet>

Positional:
  subnet                  Target subnet in CIDR notation (e.g., 192.168.1.0/24)

Options:
  --output-dir, -o DIR    Output directory (default: ./results)
  --full-scan             Scan all 65535 TCP ports (default: top 100)
  --timeout, -t SECONDS   Per-host timeout (default: 2)
  --no-diagram            Skip topology diagram generation
  --csv                   Also export CSV report
  --verbose, -v           Enable verbose output
```

### Interactive prompts
The tool will prompt you for SNMP settings at startup:
```
[?] Skip SNMP scanning? (y/N): 
[?] SNMP Version (1/2c) [1]: 
[?] SNMP Community String [public]: 
```

## Output

All results are saved to the `--output-dir` directory (default: `./results/`):

| File | Description |
|------|-------------|
| `scan_<subnet>_<timestamp>.json` | Full scan results with metadata |
| `scan_<subnet>_<timestamp>.csv` | Flattened tabular data (if `--csv`) |
| `topology_<subnet>.png` | Static network topology diagram |
| `topology_<subnet>.html` | Interactive topology (open in browser) |

## Scan Phases

1. **Host Discovery** — ARP broadcast + ICMP ping sweep to find live hosts
2. **Deep Scanning** — DNS resolution, TCP/UDP port scanning, SNMP queries
3. **Results** — Summary table, JSON/CSV export
4. **Topology Mapping** — Network diagram generation from discovered relationships

## Topology Inference

The tool uses multiple strategies to infer network topology:

1. **SNMP ARP cache** — Reads neighbor tables from SNMP-enabled devices
2. **LLDP/CDP data** — Layer 2 neighbor discovery from managed switches
3. **Gateway detection** — Identifies default gateway as central node
4. **Port heuristics** — Infers device type (router/switch/server/endpoint) from open ports
5. **Star fallback** — When insufficient data, assumes star topology around gateway

## ⚠️ Important Notes

- **Always get permission** before scanning networks you don't own
- **Root required** for ARP, ICMP, and TCP SYN scanning — the tool degrades gracefully without it
- **SNMP** defaults to v1 with community string "public" — configure as needed
- **Full port scans** (`--full-scan`) on large subnets can take a very long time

## License

For personal/educational use. Always scan responsibly.
