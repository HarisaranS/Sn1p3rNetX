"""
service_intel.py — Service intelligence layer.

Provides:
  • Port → canonical service name mapping (300+ ports)
  • Service EOL / version risk detection
  • Default credential hints
  • Protocol security classification (encrypted / plaintext)
"""

from __future__ import annotations

# ── Port → Service name (well-known + registered) ────────────────────────────
PORT_SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data",     21: "FTP",          22: "SSH",
    23: "Telnet",       25: "SMTP",         53: "DNS",
    67: "DHCP",         68: "DHCP-Client",  69: "TFTP",
    79: "Finger",       80: "HTTP",         88: "Kerberos",
    110: "POP3",        111: "RPCBind",     119: "NNTP",
    123: "NTP",         135: "MS-RPC",      137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP",        162: "SNMP-Trap",   179: "BGP",
    389: "LDAP",        443: "HTTPS",       445: "SMB",
    465: "SMTPS",       500: "IKE",         512: "rexec",
    513: "rlogin",      514: "rsh",         515: "LPD",
    554: "RTSP",        587: "SMTP-Sub",    593: "MS-RPC-HTTP",
    631: "IPP",         636: "LDAPS",       873: "Rsync",
    902: "VMware-Auth", 993: "IMAPS",       995: "POP3S",
    1080: "SOCKS",      1194: "OpenVPN",    1433: "MSSQL",
    1521: "Oracle-DB",  1723: "PPTP",       2049: "NFS",
    2121: "FTP-Alt",    2375: "Docker-HTTP",2376: "Docker-TLS",
    2379: "etcd",       2380: "etcd-peer",  3000: "Grafana",
    3128: "Squid",      3268: "AD-GC",      3306: "MySQL",
    3389: "RDP",        3390: "xRDP",       4443: "HTTPS-Alt",
    4848: "GlassFish",  5000: "Dev-Server", 5432: "PostgreSQL",
    5601: "Kibana",     5672: "RabbitMQ",   5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",6379: "Redis",
    6443: "K8s-API",    7070: "AnyDesk",    7474: "Neo4j",
    8000: "HTTP-Alt",   8080: "HTTP-Proxy", 8088: "Ambari",
    8161: "ActiveMQ",   8443: "HTTPS-Alt2", 8500: "Consul",
    8983: "Solr",       9000: "SonarQube",  9090: "Prometheus",
    9092: "Kafka",      9200: "Elasticsearch",9300: "ES-Cluster",
    10000: "Webmin",    10250: "Kubelet",   11211: "Memcached",
    15672: "RabbitMQ-Mgmt", 16379: "Redis-Cluster",
    27017: "MongoDB",   27018: "MongoDB-Shard",
    50000: "Jenkins",   50070: "HDFS-NameNode",
}

# ── Plaintext protocol set ────────────────────────────────────────────────────
PLAINTEXT_PORTS = {21, 23, 25, 53, 69, 79, 80, 110, 119, 143, 161,
                   389, 512, 513, 514, 515, 873, 8080, 8000}

# ── Version EOL database (keyword in service description → EOL notice) ────────
_EOL_DB = [
    ("openssh/4",   "OpenSSH 4.x — End of Life (pre-2012)"),
    ("openssh/5",   "OpenSSH 5.x — End of Life (pre-2014)"),
    ("openssh/6",   "OpenSSH 6.x — End of Life (pre-2016)"),
    ("openssh/7.2", "OpenSSH 7.2 — multiple known CVEs, upgrade recommended"),
    ("apache/2.2",  "Apache 2.2 — End of Life since 2018"),
    ("apache/2.4.1","Apache 2.4.1-2.4.50 — multiple critical CVEs (path traversal)"),
    ("nginx/1.14",  "nginx 1.14 — legacy stable, upgrade to 1.24+"),
    ("nginx/1.16",  "nginx 1.16 — legacy stable branch"),
    ("mysql/5",     "MySQL 5.x — End of Life, multiple known auth bypass CVEs"),
    ("mariadb/10.3","MariaDB 10.3 — reached EOL in 2023"),
    ("php/5",       "PHP 5.x — End of Life (pre-2019)"),
    ("php/7.0",     "PHP 7.0 — End of Life"),
    ("php/7.1",     "PHP 7.1 — End of Life"),
    ("php/7.2",     "PHP 7.2 — End of Life"),
    ("openssl/1.0", "OpenSSL 1.0 — End of Life (2020), critical CVEs"),
    ("openssl/1.1", "OpenSSL 1.1 — EOL September 2023"),
    ("tomcat/7",    "Tomcat 7.x — End of Life"),
    ("tomcat/8.0",  "Tomcat 8.0.x — End of Life"),
    ("java/1.7",    "Java 7 — End of Life"),
    ("java/1.8",    "Java 8 — Legacy; security-update cadence slowing"),
    ("windows xp",  "Windows XP — End of Life (2014) — critical exposure"),
    ("windows 7",   "Windows 7 — End of Life (2020) — no security patches"),
    ("windows server 2003", "Windows Server 2003 — End of Life"),
    ("windows server 2008", "Windows Server 2008 — End of Life (2020)"),
]

# ── Default credential hints ───────────────────────────────────────────────────
_DEFAULT_CREDS = {
    "mysql":        "root / (empty) or root / root",
    "mongodb":      "no auth by default (pre-3.6)",
    "redis":        "no auth by default — CONFIG SET requirepass",
    "postgresql":   "postgres / postgres",
    "mssql":        "sa / (empty) or sa / password",
    "jenkins":      "admin / admin (first-run setup)",
    "grafana":      "admin / admin",
    "kibana":       "elastic / changeme",
    "rabbitmq":     "guest / guest",
    "vnc":          "often blank or simple password",
    "wazuh":        "admin / admin (default dashboard)",
    "consul":       "no token by default (HTTP API open)",
    "prometheus":   "no auth by default",
    "glassfish":    "admin / adminadmin",
    "webmin":       "root / (system root password)",
    "sonarqube":    "admin / admin",
    "vault":        "requires init, root token exposed sometimes",
}


def get_service_name(port: int) -> str:
    """Return canonical service name for port, or 'Unknown'."""
    return PORT_SERVICE_MAP.get(port, "Unknown")


def get_eol_warnings(service_description: str) -> list[str]:
    """Return EOL notices that match the service description."""
    desc_lower = service_description.lower()
    return [
        notice
        for keyword, notice in _EOL_DB
        if keyword.lower() in desc_lower
    ]


def get_default_creds_hint(service_description: str) -> str | None:
    """Return default credentials hint for a matched service, or None."""
    desc_lower = service_description.lower()
    for keyword, hint in _DEFAULT_CREDS.items():
        if keyword in desc_lower:
            return hint
    return None


def is_plaintext_protocol(port: int) -> bool:
    """Return True if this port uses a cleartext protocol."""
    return port in PLAINTEXT_PORTS


def enrich_services_with_intel(scan_results: list) -> list:
    """
    Add service_name, eol_warnings, default_creds_hint, and is_plaintext
    to every service dict.
    """
    for host in scan_results:
        for svc in host.get("services", []):
            port = int(svc.get("port", 0))
            desc = svc.get("description", "")

            svc["service_name"]       = get_service_name(port) or svc.get("name", "")
            svc["eol_warnings"]       = get_eol_warnings(desc)
            svc["default_creds_hint"] = get_default_creds_hint(desc)
            svc["is_plaintext"]       = is_plaintext_protocol(port)
    return scan_results
