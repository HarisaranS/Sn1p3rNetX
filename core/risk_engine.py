"""
risk_engine.py — Enterprise-grade risk scoring engine.

Scoring model:
  • Base: 1 pt per open port  (surface area)
  • Port weight: critical ports (RDP, MySQL exposed, Telnet …) carry fixed bonus pts
  • CVE severity: CRITICAL=15, HIGH=10, MEDIUM=5, LOW=2
  • CVSS amplifier: score *= (1 + max_cvss / 40)  [caps amplification at +25%]
  • Attack-combination bonus: e.g. RDP + MySQL together adds +10
  • Cap at 100

Levels: ≥75 CRITICAL | ≥45 HIGH | ≥20 MEDIUM | else LOW

Also generates:
  • device_type classification
  • attack_surface_index  (ratio of dangerous ports to total)
  • mitre_techniques       (relevant ATT&CK technique IDs)
"""

from __future__ import annotations
from typing import Any

# ── Port weight table (port → bonus score points) ─────────────────────────────
_PORT_WEIGHTS: dict[int, int] = {
    21:    8,   # FTP — plaintext creds
    22:    3,   # SSH — brute-force target
    23:   18,   # Telnet — critical
    25:    5,   # SMTP
    53:    4,   # DNS
    80:    2,   # HTTP
    110:   4,   # POP3
    111:   8,   # rpcbind
    135:   8,   # MS RPC
    139:  12,   # NetBIOS
    161:   8,   # SNMP
    389:   5,   # LDAP
    443:   1,   # HTTPS (low weight — encrypted)
    445:  18,   # SMB/EternalBlue
    512:  15,   # rexec
    513:  15,   # rlogin
    514:  18,   # rsh
    902:  10,   # VMware auth
    1433: 12,   # MSSQL
    1521: 12,   # Oracle
    2049:  8,   # NFS
    3306: 12,   # MySQL
    3389: 18,   # RDP
    3390: 15,   # xrdp
    4848: 10,   # GlassFish admin
    5432: 10,   # PostgreSQL
    5900: 15,   # VNC
    5985: 10,   # WinRM
    6379: 18,   # Redis
    7070:  6,   # AnyDesk relay
    8080:  3,   # HTTP alt
    8443:  1,   # HTTPS alt
    9200: 10,   # Elasticsearch/OpenSearch
    9300:  8,   # Elasticsearch cluster
    11211:10,   # Memcached
    27017:18,   # MongoDB
    27018:15,   # MongoDB shard
}

# ── Device classification heuristics ─────────────────────────────────────────
_DEVICE_PROFILES = [
    ("Security Appliance (SIEM)",  [443, 9200, 9300], ["wazuh", "opensearch", "kibana"]),
    ("Database Server",            [3306, 5432, 1433, 27017, 6379], ["mysql", "postgres", "mssql", "mongodb", "redis"]),
    ("Windows Workstation/Server", [3389, 445, 135, 139], ["windows", "microsoft"]),
    ("Linux Server",               [22, 80, 443, 111], ["linux", "ubuntu", "debian", "centos"]),
    ("VMware Hypervisor",          [902], ["vmware", "esxi"]),
    ("Remote Access Server",       [3389, 3390, 5900, 7070], ["rdp", "vnc", "anydesk", "xrdp"]),
    ("Web Server",                 [80, 443, 8080, 8443], ["apache", "nginx", "iis", "tomcat"]),
    ("Network Device",             [23, 161, 22, 80], ["cisco", "juniper", "mikrotik", "fortinet"]),
    ("IoT / Camera",               [554, 8000, 8080, 80], ["hikvision", "axis", "dahua", "rtsp"]),
    ("Development Server",         [8080, 8443, 9000, 3000, 5000], ["jenkins", "gitlab", "docker"]),
]

# ── MITRE ATT&CK technique mapping ───────────────────────────────────────────
_MITRE_MAP = {
    "rdp":         ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    "ssh":         ("T1021.004", "Remote Services: SSH"),
    "smb":         ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ftp":         ("T1071.002", "Application Layer Protocol: File Transfer"),
    "telnet":      ("T1021.004", "Remote Services: SSH (Telnet fallback)"),
    "vnc":         ("T1021.005", "Remote Services: VNC"),
    "mysql":       ("T1505.001", "Server Software Component: SQL Stored Procedures"),
    "mssql":       ("T1505.001", "Server Software Component: SQL"),
    "mongodb":     ("T1530",     "Data from Cloud Storage"),
    "redis":       ("T1505",     "Server Software Component"),
    "snmp":        ("T1046",     "Network Service Scanning"),
    "http":        ("T1190",     "Exploit Public-Facing Application"),
    "apache":      ("T1190",     "Exploit Public-Facing Application"),
    "nginx":       ("T1190",     "Exploit Public-Facing Application"),
    "tomcat":      ("T1190",     "Exploit Public-Facing Application"),
    "docker":      ("T1610",     "Deploy Container"),
    "jenkins":     ("T1072",     "Software Deployment Tools"),
    "vmware":      ("T1610",     "Deploy Container / Hypervisor abuse"),
    "anydesk":     ("T1219",     "Remote Access Software"),
    "teamviewer":  ("T1219",     "Remote Access Software"),
    "ldap":        ("T1087.002", "Account Discovery: Domain Account"),
}


def _classify_device(ports: list[int], services: list[dict]) -> str:
    """Return the best-fit device type label."""
    service_text = " ".join(
        s.get("description", "") + " " + s.get("name", "")
        for s in services
    ).lower()
    port_set = set(ports)

    best_label = "Unknown Device"
    best_score = 0
    for label, sig_ports, sig_keywords in _DEVICE_PROFILES:
        port_hits    = len(port_set & set(sig_ports))
        keyword_hits = sum(1 for kw in sig_keywords if kw in service_text)
        score = port_hits * 2 + keyword_hits * 3
        if score > best_score:
            best_score = score
            best_label = label

    return best_label


def _extract_mitre(services: list[dict]) -> list[dict]:
    """Return MITRE ATT&CK techniques relevant to this host's services."""
    seen = set()
    techniques = []
    for svc in services:
        desc = (svc.get("description", "") + " " + svc.get("name", "")).lower()
        for keyword, (tid, tname) in _MITRE_MAP.items():
            if keyword in desc and tid not in seen:
                techniques.append({"technique_id": tid, "technique_name": tname})
                seen.add(tid)
    return techniques


def _attack_combination_bonus(port_set: set[int]) -> int:
    """Return bonus points for dangerous port combinations."""
    bonus = 0
    # RDP + database exposure
    if {3389, 3306} & port_set == {3389, 3306}:
        bonus += 10
    # SMB + no firewall implied
    if 445 in port_set or 139 in port_set:
        bonus += 8
    # Admin console + database
    if {8080, 3306} & port_set == {8080, 3306}:
        bonus += 5
    # Telnet anywhere
    if 23 in port_set:
        bonus += 10
    # Redis / MongoDB public
    if port_set & {6379, 27017}:
        bonus += 12
    # Multiple remote-access tools simultaneously
    ra_ports = {3389, 3390, 5900, 7070}
    if len(port_set & ra_ports) >= 2:
        bonus += 8
    return bonus


def calculate_risk_score(host_data: dict) -> dict:
    """
    Compute the full risk profile for a single host.
    Returns a dict with: score, risk_level, metrics, device_type, mitre_techniques.
    """
    score = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    max_cvss = 0.0

    open_ports   = host_data.get("open_ports", [])
    services     = host_data.get("services", [])
    port_nums    = [int(p.split("/")[0]) for p in open_ports if "/" in p]
    port_set     = set(port_nums)

    # ── 1. Surface area ────────────────────────────────────────────────────────
    score += len(port_nums) * 1

    # ── 2. Port-weight bonus ───────────────────────────────────────────────────
    score += sum(_PORT_WEIGHTS.get(p, 0) for p in port_set)

    # ── 3. CVE / vulnerability scoring ────────────────────────────────────────
    for svc in services:
        vulns = svc.get("vulnerabilities", [])
        for v in vulns:
            sev  = v.get("severity", "LOW").upper()
            cvss = float(v.get("cvss_score", 0))
            max_cvss = max(max_cvss, cvss)

            if sev == "CRITICAL":
                score += 15
                severity_counts["CRITICAL"] += 1
            elif sev == "HIGH":
                score += 10
                severity_counts["HIGH"] += 1
            elif sev == "MEDIUM":
                score += 5
                severity_counts["MEDIUM"] += 1
            else:
                score += 2
                severity_counts["LOW"] += 1

    # ── 4. CVSS amplifier (max +25%) ──────────────────────────────────────────
    if max_cvss > 0:
        score = int(score * (1 + max_cvss / 40))

    # ── 5. Attack-combination bonus ───────────────────────────────────────────
    score += _attack_combination_bonus(port_set)

    # ── 6. Cap ────────────────────────────────────────────────────────────────
    score = min(score, 100)

    # ── 7. Risk level ─────────────────────────────────────────────────────────
    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 45:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── 8. Device classification ──────────────────────────────────────────────
    device_type = _classify_device(port_nums, services)

    # ── 9. MITRE ATT&CK mapping ───────────────────────────────────────────────
    mitre_techniques = _extract_mitre(services)

    # ── 10. Attack surface index ──────────────────────────────────────────────
    risky_port_count = sum(1 for p in port_set if _PORT_WEIGHTS.get(p, 0) >= 8)
    attack_surface_index = (
        round(risky_port_count / len(port_set) * 100, 1) if port_set else 0.0
    )

    return {
        "score":      score,
        "risk_level": risk_level,
        "metrics": {
            "critical_cves":       severity_counts["CRITICAL"],
            "high_cves":           severity_counts["HIGH"],
            "medium_cves":         severity_counts["MEDIUM"],
            "low_cves":            severity_counts["LOW"],
            "total_open_ports":    len(port_set),
            "max_cvss":            max_cvss,
            "attack_surface_idx":  attack_surface_index,
        },
        "device_type":       device_type,
        "mitre_techniques":  mitre_techniques,
    }


def process_risk_for_hosts(scan_results: list) -> list:
    """Enrich every host dict in-place with full risk profile."""
    for host in scan_results:
        risk = calculate_risk_score(host)
        host["risk_score"]       = risk["score"]
        host["risk_level"]       = risk["risk_level"]
        host["risk_metrics"]     = risk["metrics"]
        host["device_type"]      = risk["device_type"]
        host["mitre_techniques"] = risk["mitre_techniques"]
    return scan_results
