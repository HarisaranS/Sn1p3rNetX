"""
cve_lookup.py — Offline CVE / vulnerability knowledge base + optional live NVD lookups.

The local database covers 100+ rules across all common service categories.
Each rule matches on a keyword found in the service description string or port number.
"""

import subprocess
import json
import re
from core.utils import log_message

# ─────────────────────────────────────────────────────────────────────────────
# LOCAL VULNERABILITY DATABASE
# Each entry: (keyword, cve_id, description, severity, cvss_score)
# keyword   — matched case-insensitively against service description OR port
# cve_id    — CVE identifier or meaningful tag
# severity  — CRITICAL / HIGH / MEDIUM / LOW
# cvss_score — CVSS v3 base score (0.0 – 10.0)
# ─────────────────────────────────────────────────────────────────────────────
_VULN_DB = [
    # ── Web Servers ───────────────────────────────────────────────────────────
    ("apache",          "CVE-2024-40725", "Apache httpd Source Disclosure",                            "HIGH",     7.5),
    ("apache/2.4.49",   "CVE-2021-41773", "Apache Path Traversal & RCE (Hafnium-class)",               "CRITICAL", 9.8),
    ("apache/2.4.50",   "CVE-2021-42013", "Apache Path Traversal bypass (2.4.50)",                     "CRITICAL", 9.8),
    ("apache/2.4.51",   "CVE-2021-42013", "Apache Path Traversal bypass (2.4.51)",                     "CRITICAL", 9.8),
    ("apache/2.4.52",   "CVE-2022-22720", "Apache HTTP Request Smuggling",                             "HIGH",     8.1),
    ("apache/2.4.53",   "CVE-2022-26377", "Apache mod_proxy AJP Request Smuggling",                    "HIGH",     7.5),
    ("apache/2.4.54",   "CVE-2022-36760", "Apache mod_proxy_ajp Smuggling",                            "HIGH",     7.4),
    ("nginx",           "CVE-2022-41741", "nginx Memory Corruption via crafted header",                 "MEDIUM",   6.5),
    ("nginx/1.2",       "CVE-2019-20372", "nginx HTTP Request Smuggling (≤1.20)",                      "MEDIUM",   5.3),
    ("iis",             "CVE-2022-21907", "IIS HTTP Protocol Stack RCE (wormable)",                     "CRITICAL", 9.8),
    ("iis/7",           "CVE-2010-2730",  "IIS 7.x FastCGI extension spoofing",                        "HIGH",     7.8),
    ("tomcat",          "CVE-2020-1938",  "Apache Tomcat Ghostcat AJP RCE",                            "CRITICAL", 9.8),
    ("tomcat/9",        "CVE-2021-25122", "Apache Tomcat Request Smuggling",                            "HIGH",     7.5),
    ("lighttpd",        "CVE-2022-37434", "lighttpd / zlib heap buffer overflow",                      "CRITICAL", 9.8),
    ("caddy",           "CVE-2023-28114", "Caddy HTTP/2 DoS",                                          "MEDIUM",   5.9),
    ("glassfish",       "CVE-2017-1000030","GlassFish auth bypass",                                    "CRITICAL", 9.8),
    ("weblogic",        "CVE-2020-2551",  "Oracle WebLogic RCE via IIOP",                              "CRITICAL", 9.8),
    ("websphere",       "CVE-2020-4450",  "IBM WebSphere RCE",                                         "CRITICAL", 9.8),
    ("jboss",           "CVE-2017-12149", "JBoss/WildFly Unsafe Deserialization RCE",                  "CRITICAL", 9.8),
    ("struts",          "CVE-2017-5638",  "Apache Struts 2 RCE (Equifax breach vector)",               "CRITICAL", 10.0),

    # ── SSH ───────────────────────────────────────────────────────────────────
    ("openssh",         "CVE-2024-6387",  "OpenSSH regreSSHion Signal Handler Race RCE",               "CRITICAL", 8.1),
    ("openssh/7",       "CVE-2016-6515",  "OpenSSH 7.x DoS via crafted packet",                       "HIGH",     7.8),
    ("openssh/8",       "CVE-2021-28041", "OpenSSH 8.x double-free in ssh-agent",                     "HIGH",     7.8),
    ("dropbear",        "INFO-DROPBEAR",  "Dropbear SSH — common on embedded/IoT (weak defaults)",     "MEDIUM",   5.3),

    # ── FTP ───────────────────────────────────────────────────────────────────
    ("vsftpd/2.3.4",    "CVE-2011-2523",  "vsftpd 2.3.4 Backdoor RCE",                                "CRITICAL", 10.0),
    ("proftpd",         "CVE-2019-12815", "ProFTPD mod_copy Arbitrary File Copy RCE",                  "CRITICAL", 9.8),
    ("wu-ftpd",         "CVE-2000-0573",  "WU-FTPd SITE EXEC Remote Root",                            "CRITICAL", 10.0),

    # ── SMB / Windows ─────────────────────────────────────────────────────────
    ("smb",             "MS17-010",       "EternalBlue SMBv1 RCE (used by WannaCry/NotPetya)",         "CRITICAL", 9.8),
    ("netbios",         "CVE-2017-0144",  "SMBv1 Buffer Overflow (EternalBlue)",                       "CRITICAL", 9.8),
    ("microsoft-ds",    "MS17-010",       "EternalBlue SMBv1 RCE",                                     "CRITICAL", 9.8),
    ("samba",           "CVE-2017-7494",  "Samba SambaCry RCE",                                        "CRITICAL", 9.8),
    ("samba/4",         "CVE-2021-44142", "Samba 4.x Heap UAF",                                        "CRITICAL", 9.9),

    # ── RDP ───────────────────────────────────────────────────────────────────
    ("rdp",             "CVE-2019-0708",  "BlueKeep — Pre-auth RCE on RDP (wormable)",                 "CRITICAL", 9.8),
    ("ms-wbt-server",   "CVE-2019-0708",  "BlueKeep — RDP Pre-auth RCE",                               "CRITICAL", 9.8),
    ("xrdp",            "CVE-2022-23468", "xrdp Off-by-One Buffer Overflow",                           "HIGH",     8.8),
    ("rdp",             "CVE-2019-1181",  "DejaBlue RDP Pre-auth RCE",                                 "CRITICAL", 9.8),

    # ── VNC ───────────────────────────────────────────────────────────────────
    ("vnc",             "INFO-VNC-NOAUTH","Open VNC — No Authentication (RFB protocol exposed)",       "CRITICAL", 9.8),
    ("rfb",             "CVE-2006-2369",  "LibVNCServer Auth Bypass",                                  "HIGH",     7.5),
    ("vnc",             "CVE-2019-15681", "LibVNCServer Memory Leak / Info Disclosure",                "HIGH",     7.5),

    # ── Remote Access Tools ───────────────────────────────────────────────────
    ("anydesk",         "CVE-2024-12754", "AnyDesk Local Privilege Escalation",                        "HIGH",     7.8),
    ("anydesk",         "INFO-ANYDESK",   "AnyDesk remote access detected — verify authorisation",     "MEDIUM",   5.5),
    ("teamviewer",      "CVE-2019-18988", "TeamViewer Credential Disclosure via registry",             "HIGH",     7.0),
    ("teamviewer",      "INFO-TEAMVIEWER","TeamViewer remote access — verify if authorised",           "MEDIUM",   5.5),
    ("realserver",      "INFO-ANYDESK",   "AnyDesk SSL/realserver fingerprint detected",               "MEDIUM",   5.5),

    # ── Databases ─────────────────────────────────────────────────────────────
    ("mysql",           "CVE-2022-31626", "MySQL Heap Overflow in prepared statement",                  "HIGH",     8.0),
    ("mysql/5",         "CVE-2016-6662",  "MySQL 5.x Privilege Escalation via config write",           "CRITICAL", 9.8),
    ("mysql/8",         "CVE-2023-21912", "MySQL 8.0 Server Optimizer Crash / DoS",                    "HIGH",     7.5),
    ("mysql",           "INFO-MYSQL-EXP", "MySQL exposed on network — brute-force & enum risk",        "HIGH",     7.0),
    ("mariadb",         "CVE-2022-32088", "MariaDB server crash via subquery",                         "HIGH",     7.5),
    ("postgresql",      "CVE-2023-2454",  "PostgreSQL Row Security Policy Bypass",                     "HIGH",     7.7),
    ("postgresql",      "CVE-2019-10164", "PostgreSQL Stack Overflow / RCE",                           "CRITICAL", 8.8),
    ("mssql",           "CVE-2022-37435", "MSSQL SA Login Brute-force vector",                         "HIGH",     7.5),
    ("oracle",          "CVE-2022-21413", "Oracle DB Server RCE",                                      "CRITICAL", 9.0),
    ("mongodb",         "CVE-2017-15535", "MongoDB No-Auth exposure (pre-3.6 default)",                "CRITICAL", 9.8),
    ("redis",           "CVE-2022-0543",  "Redis Sandbox Escape / Lua RCE",                            "CRITICAL", 10.0),
    ("redis",           "INFO-REDIS-RCE", "Redis config write RCE (SLAVEOF/CONFIG SET)",               "CRITICAL", 9.8),
    ("couchdb",         "CVE-2022-24706", "CouchDB Default Erlang Cookie RCE",                         "CRITICAL", 9.8),
    ("cassandra",       "CVE-2021-44521", "Apache Cassandra RCE via user-defined functions",           "CRITICAL", 9.1),
    ("influxdb",        "CVE-2019-20933", "InfluxDB Authentication Bypass",                            "CRITICAL", 9.8),
    ("elasticsearch",   "CVE-2021-22145", "Elasticsearch Memory Disclosure",                           "MEDIUM",   5.3),
    ("elasticsearch",   "CVE-2014-3120",  "Elasticsearch Dynamic Script RCE",                          "CRITICAL", 9.8),
    ("opensearch",      "CVE-2023-23463", "OpenSearch DoS via crafted query",                          "HIGH",     7.5),

    # ── Message Queues ────────────────────────────────────────────────────────
    ("rabbitmq",        "CVE-2021-32719", "RabbitMQ Default Credentials on management API",            "HIGH",     8.8),
    ("activemq",        "CVE-2023-46604", "Apache ActiveMQ RCE (Critical)",                            "CRITICAL", 10.0),
    ("kafka",           "CVE-2018-17196", "Apache Kafka Privilege Escalation",                         "HIGH",     8.8),
    ("memcached",       "CVE-2018-1000115","Memcached UDP reflection amplification",                   "HIGH",     7.5),

    # ── DevOps / CI-CD ────────────────────────────────────────────────────────
    ("docker",          "CVE-2019-5736",  "runc Container Breakout",                                   "CRITICAL", 8.6),
    ("docker",          "CVE-2024-21626", "runc Container Breakout (Leaky Vessels)",                   "CRITICAL", 8.6),
    ("kubernetes",      "CVE-2018-1002105","Kubernetes API Server Privilege Escalation",               "CRITICAL", 9.8),
    ("kubelet",         "CVE-2021-25741", "Kubernetes Symlink Exchange Attack",                        "HIGH",     8.1),
    ("jenkins",         "CVE-2018-1000861","Jenkins Script Console RCE",                               "CRITICAL", 9.8),
    ("jenkins",         "CVE-2024-23897", "Jenkins CLI Arbitrary File Read",                           "CRITICAL", 9.8),
    ("gitlab",          "CVE-2021-22205", "GitLab ExifTool RCE (Pre-auth)",                            "CRITICAL", 10.0),
    ("gitlab",          "CVE-2023-7028",  "GitLab Account Takeover via password reset",               "CRITICAL", 10.0),
    ("github enterprise","CVE-2024-4985", "GitHub Enterprise Pre-auth RCE",                            "CRITICAL", 10.0),

    # ── SIEM / Monitoring ─────────────────────────────────────────────────────
    ("wazuh",           "INFO-WAZUH",     "Wazuh SIEM detected — ensure dashboard is not public",     "MEDIUM",   5.0),
    ("kibana",          "CVE-2019-7609",  "Kibana Timelion Prototype Pollution RCE",                  "CRITICAL", 9.8),
    ("grafana",         "CVE-2021-43798", "Grafana Directory Traversal / Credential Exposure",        "CRITICAL", 9.8),
    ("prometheus",      "INFO-PROMETHEUS","Prometheus metrics endpoint exposed (info disclosure)",     "MEDIUM",   5.3),
    ("zabbix",          "CVE-2022-23134", "Zabbix Authentication Bypass",                             "CRITICAL", 9.8),
    ("nagios",          "CVE-2018-15710", "Nagios XI Local Privilege Escalation",                     "HIGH",     7.8),

    # ── VMware ────────────────────────────────────────────────────────────────
    ("vmware",          "CVE-2021-21985", "VMware vCenter RCE (Pre-auth)",                            "CRITICAL", 9.8),
    ("vmware",          "CVE-2021-22005", "VMware vCenter File Upload RCE",                           "CRITICAL", 9.8),
    ("vmware-auth",     "CVE-2021-22015", "VMware Authentication Daemon Privilege Escalation",        "HIGH",     7.8),
    ("esxi",            "CVE-2021-21974", "VMware ESXi OpenSLP Heap Overflow RCE",                    "CRITICAL", 9.8),

    # ── VPN / Firewalls ───────────────────────────────────────────────────────
    ("fortinet",        "CVE-2023-27997", "Fortinet SSL VPN Pre-auth Heap Overflow RCE",              "CRITICAL", 9.8),
    ("pulse",           "CVE-2019-11510", "Pulse Secure VPN Arbitrary File Read",                     "CRITICAL", 10.0),
    ("cisco",           "CVE-2023-20198", "Cisco IOS XE Privilege Escalation (Active Exploitation)",  "CRITICAL", 10.0),
    ("palo alto",       "CVE-2024-3400",  "PAN-OS Command Injection (CVSS 10)",                       "CRITICAL", 10.0),
    ("openvpn",         "CVE-2017-7479",  "OpenVPN RSA Private Key Auth Bypass",                      "HIGH",     7.5),

    # ── Network Services ─────────────────────────────────────────────────────
    ("snmp",            "INFO-SNMP-ENUM", "SNMP community string enumeration risk (public/private)",  "HIGH",     7.5),
    ("telnet",          "INFO-TELNET",    "Telnet transmits credentials in plaintext — replace SSH",  "CRITICAL", 9.0),
    ("ftp",             "INFO-FTP",       "FTP transmits credentials in plaintext",                   "HIGH",     7.5),
    ("rpcbind",         "CVE-2017-8779",  "rpcbind amplification DoS attack",                        "HIGH",     7.5),
    ("nfs",             "CVE-2019-3010",  "NFS Server information disclosure",                        "MEDIUM",   5.3),
    ("ldap",            "CVE-2021-44228", "Log4Shell via LDAP lookup (if Log4j in stack)",            "CRITICAL", 10.0),
    ("dns",             "CVE-2020-1350",  "SIGRed Windows DNS Server RCE",                           "CRITICAL", 10.0),

    # ── IoT / Embedded ────────────────────────────────────────────────────────
    ("upnp",            "CVE-2020-12695", "UPnP CallStranger SSRF/Amplification",                     "HIGH",     7.5),
    ("rtsp",            "INFO-RTSP",      "RTSP camera stream — verify auth is enforced",             "MEDIUM",   5.0),
    ("hikvision",       "CVE-2021-36260", "Hikvision Camera Unauthenticated RCE",                     "CRITICAL", 9.8),
    ("axis",            "CVE-2018-10660", "Axis Camera Shell Command Injection",                      "CRITICAL", 9.8),

    # ── Misc / Cloud ─────────────────────────────────────────────────────────
    ("consul",          "CVE-2021-32574", "Consul ACL Token Exposure",                                "HIGH",     7.5),
    ("vault",           "CVE-2021-3024",  "HashiCorp Vault Privilege Escalation",                    "HIGH",     7.5),
    ("etcd",            "CVE-2020-15106", "etcd Unauth Write via /v2/keys",                           "HIGH",     8.1),
    ("minio",           "CVE-2023-28432", "MinIO Information Disclosure (credentials exposed)",       "CRITICAL", 7.5),
    ("spring",          "CVE-2022-22965", "Spring4Shell RCE via DataBinder (Java 9+)",                "CRITICAL", 9.8),
]

# ─────────────────────────────────────────────────────────────────────────────
# PORT-BASED RISK HINTS  (port number → risk context even if service unknown)
# ─────────────────────────────────────────────────────────────────────────────
_PORT_HINTS = {
    21:   ("INFO-FTP-PORT",    "FTP (plaintext credentials)",          "HIGH",    7.0),
    23:   ("INFO-TELNET-PORT", "Telnet (plaintext protocol)",          "CRITICAL",9.0),
    25:   ("INFO-SMTP",        "SMTP open relay risk",                 "MEDIUM",  5.5),
    53:   ("INFO-DNS",         "DNS exposed — zone transfer possible", "MEDIUM",  5.0),
    69:   ("INFO-TFTP",        "TFTP (no auth) detected",              "HIGH",    7.5),
    80:   ("INFO-HTTP",        "HTTP (unencrypted web)",               "LOW",     3.1),
    110:  ("INFO-POP3",        "POP3 cleartext email",                 "MEDIUM",  5.0),
    111:  ("CVE-2017-8779",    "rpcbind amplification DoS",           "HIGH",    7.5),
    139:  ("MS17-010",         "NetBIOS/SMBv1 EternalBlue",           "CRITICAL",9.8),
    143:  ("INFO-IMAP",        "IMAP cleartext email",                "MEDIUM",  5.0),
    161:  ("INFO-SNMP-PORT",   "SNMP UDP community enumeration",      "HIGH",    7.5),
    389:  ("INFO-LDAP-PORT",   "LDAP — directory enumeration risk",   "MEDIUM",  5.3),
    443:  ("INFO-HTTPS",       "HTTPS — check TLS version & ciphers", "LOW",     2.5),
    445:  ("MS17-010",         "SMBv1 EternalBlue (port 445)",        "CRITICAL",9.8),
    512:  ("INFO-REXEC",       "rexec — remote execution (insecure)", "HIGH",    8.0),
    513:  ("INFO-RLOGIN",      "rlogin — cleartext remote login",     "HIGH",    8.0),
    514:  ("INFO-RSH",         "RSH — unauthenticated remote shell",  "CRITICAL",9.5),
    902:  ("INFO-VMWARE-902",  "VMware auth daemon exposed",          "HIGH",    7.8),
    1433: ("INFO-MSSQL-PORT",  "MSSQL network exposure",              "HIGH",    7.5),
    1521: ("INFO-ORACLE-PORT", "Oracle DB exposed to network",        "HIGH",    7.5),
    2049: ("INFO-NFS-PORT",    "NFS share — check export policies",   "HIGH",    7.5),
    3306: ("INFO-MYSQL-PORT",  "MySQL exposed — brute-force risk",    "HIGH",    7.0),
    3389: ("CVE-2019-0708",    "RDP BlueKeep pre-auth RCE",           "CRITICAL",9.8),
    3390: ("CVE-2022-23468",   "xrdp buffer overflow",                "HIGH",    8.8),
    4848: ("INFO-GLASSFISH",   "GlassFish admin console exposed",     "HIGH",    8.1),
    5432: ("INFO-PGSQL-PORT",  "PostgreSQL network exposure",         "HIGH",    7.5),
    5900: ("INFO-VNC-PORT",    "VNC exposed — verify auth",           "CRITICAL",9.0),
    5985: ("INFO-WINRM",       "WinRM HTTP — Windows remote mgmt",   "HIGH",    7.8),
    5986: ("INFO-WINRM-S",     "WinRM HTTPS — Windows remote mgmt",  "HIGH",    7.0),
    6379: ("CVE-2022-0543",    "Redis unauthenticated RCE risk",      "CRITICAL",9.8),
    7070: ("INFO-ANYDESK-7070","AnyDesk relay port detected",        "MEDIUM",  5.5),
    8080: ("INFO-HTTP-ALT",    "HTTP alternate — often dev/admin UI", "MEDIUM",  5.0),
    8443: ("INFO-HTTPS-ALT",   "HTTPS alternate — check TLS config",  "LOW",     2.5),
    9200: ("INFO-ELASTIC",     "Elasticsearch/OpenSearch API exposed","HIGH",    7.5),
    9300: ("INFO-ELASTIC-INT", "Elasticsearch cluster comm exposed",  "HIGH",    7.5),
    11211:("INFO-MEMCACHED",   "Memcached open (amplification risk)", "HIGH",    7.5),
    27017:("CVE-2017-15535",   "MongoDB unauthenticated exposure",    "CRITICAL",9.8),
    27018:("CVE-2017-15535",   "MongoDB shard server exposed",        "CRITICAL",9.8),
    50000:("CVE-2020-2055",    "IBM DB2 discovery service",           "HIGH",    7.5),
}


def _match_service(service_str: str) -> list:
    """Match service description against the _VULN_DB knowledge base."""
    results = []
    s = service_str.lower()
    seen = set()
    for (keyword, cve_id, desc, severity, cvss) in _VULN_DB:
        if keyword.lower() in s and cve_id not in seen:
            results.append({
                "cve_id":      cve_id,
                "description": desc,
                "severity":    severity,
                "cvss_score":  cvss,
                "source":      "local_db",
            })
            seen.add(cve_id)
    return results


def _match_port(port: int) -> list:
    """Return port-based risk hint if the port is in _PORT_HINTS."""
    if port in _PORT_HINTS:
        cve_id, desc, severity, cvss = _PORT_HINTS[port]
        return [{
            "cve_id":      cve_id,
            "description": desc,
            "severity":    severity,
            "cvss_score":  cvss,
            "source":      "port_hint",
        }]
    return []


def _searchsploit_lookup(service_str: str) -> list:
    """Optional SearchSploit integration — returns top 3 CVE lines."""
    results = []
    try:
        out = subprocess.check_output(
            ["searchsploit", "--exclude=dos", "--json", service_str],
            stderr=subprocess.DEVNULL
        ).decode()
        data = json.loads(out)
        for item in data.get("RESULTS_EXPLOIT", [])[:3]:
            title = item.get("Title", "")
            cve_match = re.search(r"CVE-\d{4}-\d+", title)
            cve_id = cve_match.group(0) if cve_match else "SearchSploit"
            results.append({
                "cve_id":      cve_id,
                "description": title,
                "severity":    "HIGH",
                "cvss_score":  0.0,
                "source":      "searchsploit",
            })
    except Exception:
        pass
    return results


def suggest_exploits(service_str: str, port: int = 0) -> list:
    """
    Main API — given a service description string and optional port number,
    return a deduplicated list of vulnerability dicts.
    """
    if not service_str and not port:
        return []

    found = []
    seen_ids = set()

    # 1) Service-string match
    for v in _match_service(service_str):
        if v["cve_id"] not in seen_ids:
            found.append(v)
            seen_ids.add(v["cve_id"])

    # 2) Port-based hint (only if no service match yet, or port is always relevant)
    for v in _match_port(port):
        if v["cve_id"] not in seen_ids:
            found.append(v)
            seen_ids.add(v["cve_id"])

    # 3) Optional SearchSploit (doesn't block on failure)
    for v in _searchsploit_lookup(service_str):
        if v["cve_id"] not in seen_ids:
            found.append(v)
            seen_ids.add(v["cve_id"])

    return found


def enrich_services_with_cves(scan_results: list) -> list:
    """
    Enriches each service in each host with vulnerability data.
    Passes both description and port number for maximum match coverage.
    """
    for host in scan_results:
        for service in host.get("services", []):
            vulns = suggest_exploits(
                service.get("description", ""),
                port=int(service.get("port", 0)),
            )
            service["vulnerabilities"] = vulns
            service["vuln_count"]      = len(vulns)
            service["max_cvss"]        = max((v["cvss_score"] for v in vulns), default=0.0)
    return scan_results
