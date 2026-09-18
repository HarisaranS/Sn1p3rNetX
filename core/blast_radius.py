"""
blast_radius.py — Attack blast radius and lateral movement analysis.

Calculates: if host X is compromised, what can an attacker reach next?
Models the network as a directed graph and finds all reachable hosts.
"""

from __future__ import annotations
import ipaddress


# ── Port compatibility matrix: which ports allow lateral movement ──────────────
# If host A has port P open, an attacker on A can reach host B if B also has P
_LATERAL_PORTS = {
    22:    "SSH lateral movement",
    23:    "Telnet lateral movement",
    25:    "SMTP relay chain",
    53:    "DNS poisoning chain",
    80:    "HTTP service chaining",
    135:   "RPC lateral movement",
    139:   "SMB lateral movement (NetBIOS)",
    161:   "SNMP enumeration chain",
    389:   "LDAP directory traversal",
    443:   "HTTPS service chaining",
    445:   "SMB EternalBlue lateral movement",
    1433:  "MSSQL lateral movement",
    1521:  "Oracle DB lateral movement",
    2049:  "NFS mount chain",
    3306:  "MySQL credential reuse",
    3389:  "RDP lateral movement",
    3390:  "xRDP lateral movement",
    5432:  "PostgreSQL lateral movement",
    5900:  "VNC lateral movement",
    5985:  "WinRM lateral movement",
    5986:  "WinRM HTTPS lateral movement",
    6379:  "Redis unauthenticated lateral",
    8080:  "HTTP admin console chain",
    9200:  "Elasticsearch data access",
    27017: "MongoDB unauthenticated chain",
}

# ── Data sensitivity for blast radius severity ─────────────────────────────────
_DATA_SENSITIVITY = {
    "Database Server":             5,   # Direct data access
    "Security Appliance (SIEM)":   4,   # Security controls disabled
    "Windows Workstation/Server":  3,   # Credential store
    "Remote Access Server":        4,   # Gateway to everything
    "VMware Hypervisor":           5,   # All VMs at risk
    "Development Server":          3,   # Source code / secrets
    "Web Server":                  2,   # Public facing
    "Network Device":              5,   # Route traffic, capture all
    "Linux Server":                3,   # General purpose
    "IoT / Camera":                2,   # Surveillance access
    "Unknown Device":              2,   # Unknown = unpredictable
}


def _get_open_port_nums(host: dict) -> set[int]:
    """Extract integer port numbers from a host's open_ports list."""
    ports = set()
    for p in host.get("open_ports", []):
        try:
            ports.add(int(str(p).split("/")[0]))
        except (ValueError, IndexError):
            pass
    return ports


def build_reachability_graph(hosts: list[dict]) -> dict[str, list[str]]:
    """
    Build a directed reachability graph.
    Returns: {source_ip: [reachable_ips]} based on compatible open ports.
    """
    graph: dict[str, list[str]] = {h.get("ip", ""): [] for h in hosts}
    host_ports = {h.get("ip", ""): _get_open_port_nums(h) for h in hosts}

    for src in hosts:
        src_ip    = src.get("ip", "")
        src_ports = host_ports[src_ip]

        for dst in hosts:
            dst_ip = dst.get("ip", "")
            if src_ip == dst_ip:
                continue

            dst_ports = host_ports[dst_ip]
            # Lateral ports shared between src and dst
            shared = src_ports & dst_ports & set(_LATERAL_PORTS.keys())
            if shared:
                graph[src_ip].append(dst_ip)

    return graph


def calculate_blast_radius(
    compromised_ip: str,
    graph: dict[str, list[str]],
    hosts: list[dict],
) -> dict:
    """
    BFS from compromised_ip through the reachability graph.
    Returns blast radius report for that host.
    """
    host_map = {h.get("ip", ""): h for h in hosts}
    visited: set[str] = set()
    queue   = [compromised_ip]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for neighbor in graph.get(current, []):
            if neighbor not in visited:
                queue.append(neighbor)

    # Remove self
    reachable_ips = visited - {compromised_ip}
    reachable_hosts = [host_map[ip] for ip in reachable_ips if ip in host_map]

    if not reachable_hosts:
        return {
            "source_ip":            compromised_ip,
            "reachable_count":      0,
            "reachable_hosts":      [],
            "max_data_sensitivity": 0,
            "blast_severity":       "CONTAINED",
            "summary":              "Compromising this host would not grant access to other known hosts.",
        }

    max_sensitivity = max(
        _DATA_SENSITIVITY.get(h.get("device_type", "Unknown Device"), 2)
        for h in reachable_hosts
    )

    # Count critical reachable hosts
    db_count  = sum(1 for h in reachable_hosts if "Database" in h.get("device_type", ""))
    vmw_count = sum(1 for h in reachable_hosts if "VMware" in h.get("device_type", ""))
    siem_count= sum(1 for h in reachable_hosts if "SIEM" in h.get("device_type", ""))

    if max_sensitivity >= 5 or vmw_count or siem_count:
        blast_severity = "CATASTROPHIC"
    elif max_sensitivity >= 4 or db_count:
        blast_severity = "CRITICAL"
    elif max_sensitivity >= 3 or len(reachable_hosts) > 5:
        blast_severity = "HIGH"
    elif len(reachable_hosts) > 2:
        blast_severity = "MEDIUM"
    else:
        blast_severity = "LOW"

    # Build summary
    parts = []
    if db_count:
        parts.append(f"{db_count} database server(s)")
    if vmw_count:
        parts.append(f"{vmw_count} hypervisor(s)")
    if siem_count:
        parts.append(f"{siem_count} SIEM/security appliance(s)")
    remaining = len(reachable_hosts) - db_count - vmw_count - siem_count
    if remaining > 0:
        parts.append(f"{remaining} other host(s)")

    summary = (
        f"Compromising {compromised_ip} exposes {len(reachable_hosts)} additional host(s): "
        + (", ".join(parts) if parts else "various hosts")
        + "."
    )

    return {
        "source_ip":            compromised_ip,
        "reachable_count":      len(reachable_hosts),
        "reachable_hosts":      [h.get("ip") for h in reachable_hosts],
        "reachable_device_types": [h.get("device_type", "Unknown") for h in reachable_hosts],
        "max_data_sensitivity": max_sensitivity,
        "blast_severity":       blast_severity,
        "db_count":             db_count,
        "hypervisor_count":     vmw_count,
        "siem_count":           siem_count,
        "summary":              summary,
    }


def enrich_hosts_with_blast_radius(hosts: list[dict]) -> list[dict]:
    """Add blast_radius field to every host dict in-place."""
    if len(hosts) < 2:
        for host in hosts:
            host["blast_radius"] = {
                "source_ip":       host.get("ip"),
                "reachable_count": 0,
                "reachable_hosts": [],
                "blast_severity":  "CONTAINED",
                "summary":         "Single host — no lateral movement possible to other scanned hosts.",
            }
        return hosts

    graph = build_reachability_graph(hosts)
    for host in hosts:
        host["blast_radius"] = calculate_blast_radius(host.get("ip", ""), graph, hosts)
    return hosts


def format_blast_radius_section(host: dict) -> str:
    """Return a formatted blast radius summary string for terminal output."""
    br = host.get("blast_radius", {})
    if not br:
        return ""

    severity = br.get("blast_severity", "UNKNOWN")
    count    = br.get("reachable_count", 0)
    ips      = ", ".join(br.get("reachable_hosts", [])[:5])
    summary  = br.get("summary", "")

    sev_icons = {
        "CATASTROPHIC": "",
        "CRITICAL":     "",
        "HIGH":         "",
        "MEDIUM":       "",
        "LOW":          "",
        "CONTAINED":    "",
    }
    icon = sev_icons.get(severity, "")

    lines = [
        f"{icon} Blast Radius: {severity} — {count} host(s) reachable",
        f"   {summary}",
    ]
    if ips:
        lines.append(f"   Lateral targets: {ips}")

    return "\n".join(lines)
