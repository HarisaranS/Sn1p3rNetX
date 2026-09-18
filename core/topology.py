"""
topology.py — Network topology analysis and device mapping.

Classifies hosts, infers network roles, and builds an ASCII network map.
"""

from __future__ import annotations
import ipaddress


# ── Device icons for ASCII map ────────────────────────────────────────────────
_ICONS = {
    "Security Appliance (SIEM)":  "  SIEM",
    "Database Server":             "  DB  ",
    "Windows Workstation/Server":  "  WIN ",
    "Linux Server":                "  LNX ",
    "VMware Hypervisor":           "  VMW ",
    "Remote Access Server":        "  RAS ",
    "Web Server":                  "  WEB ",
    "Network Device":              "  NET ",
    "IoT / Camera":                "  IoT ",
    "Development Server":          "  DEV ",
    "Unknown Device":              "  ???  ",
}

_RISK_COLORS = {
    "CRITICAL": "",
    "HIGH":     "",
    "MEDIUM":   "",
    "LOW":      "",
}


def infer_gateway(hosts: list[dict]) -> str | None:
    """
    Attempt to identify the network gateway.
    Heuristic: lowest IP in the subnet that responds.
    """
    ips = []
    for h in hosts:
        try:
            ips.append(ipaddress.ip_address(h["ip"]))
        except Exception:
            pass
    if not ips:
        return None
    return str(min(ips))


def get_subnet_summary(hosts: list[dict]) -> dict:
    """Return aggregate stats for the scanned network."""
    if not hosts:
        return {}

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_ports   = 0
    total_cves    = 0
    device_types: dict[str, int] = {}

    for h in hosts:
        level = h.get("risk_level", "LOW")
        risk_counts[level] = risk_counts.get(level, 0) + 1
        total_ports += h.get("risk_metrics", {}).get("total_open_ports", 0)
        total_cves  += (
            h.get("risk_metrics", {}).get("critical_cves", 0) +
            h.get("risk_metrics", {}).get("high_cves", 0)
        )
        dt = h.get("device_type", "Unknown Device")
        device_types[dt] = device_types.get(dt, 0) + 1

    avg_score = (
        sum(h.get("risk_score", 0) for h in hosts) / len(hosts)
    )

    return {
        "host_count":       len(hosts),
        "avg_risk_score":   round(avg_score, 1),
        "risk_distribution": risk_counts,
        "total_open_ports": total_ports,
        "total_high_cves":  total_cves,
        "device_breakdown": device_types,
        "gateway":          infer_gateway(hosts),
    }


def build_ascii_topology(hosts: list[dict]) -> str:
    """
    Render a simple ASCII network topology map showing hosts,
    their device types, risk levels, and open port counts.
    """
    if not hosts:
        return "  (no hosts to map)"

    summary = get_subnet_summary(hosts)
    gateway = summary.get("gateway")

    lines = []
    lines.append("    NETWORK TOPOLOGY MAP".center(66))
    lines.append("")

    # Simulated internet/gateway node
    lines.append("           [ INTERNET / GATEWAY ]".center(66))
    lines.append("                    │".center(66))
    lines.append("           ┌────────┴────────┐".center(66))
    lines.append("           │  LOCAL NETWORK   │".center(66))
    lines.append("           └─────────────────-┘".center(66))

    # Sort hosts by risk score descending
    sorted_hosts = sorted(hosts, key=lambda h: h.get("risk_score", 0), reverse=True)

    for h in sorted_hosts:
        ip         = h.get("ip", "?")
        risk       = h.get("risk_level", "LOW")
        score      = h.get("risk_score", 0)
        ports      = h.get("risk_metrics", {}).get("total_open_ports", 0)
        device     = h.get("device_type", "Unknown Device")
        icon       = _ICONS.get(device, "  ???  ")
        risk_dot   = _RISK_COLORS.get(risk, "")
        marker     = f" {risk_dot} {ip:<15} {icon:<12} Score:{score:>3}/100  Ports:{ports}"
        lines.append("           ├── " + marker)

    lines.append("")

    # Summary footer
    rc = summary.get("risk_distribution", {})
    footer = (
        f"  Hosts:{summary['host_count']}  "
        f"Avg:{summary['avg_risk_score']}  "
        f"Crit:{rc.get('CRITICAL',0)} High:{rc.get('HIGH',0)} "
        f"Med:{rc.get('MEDIUM',0)} Low:{rc.get('LOW',0)}"
    )
    lines.append(footer)

    return "\n".join(lines)
