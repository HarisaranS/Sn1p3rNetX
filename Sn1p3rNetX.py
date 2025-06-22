import nmap
import os
import subprocess
import re
import json
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup
from datetime import datetime
from pyfiglet import Figlet
from rich.console import Console

console = Console()
log_file = f"logs/scan_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
CACHE_FILE = ".mac_cache.json"
mac_cache={}

if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE,"r") as f:
        mac_cache=json.load(f)

def printBanner():
    f=Figlet(font='slant')
    console.print(f.renderText("Sn1p3rNetX"),style='bold red')
    

def log(msg):
    os.makedirs("logs",exist_ok=True)
    with open(log_file, "a") as logf:
        logf.write(msg+"\n")
        
def get_mac(ip):
    mac=get_mac_address(ip=ip)
    if not mac :
        try:
            output=subprocess.check_output(f"arp -n {ip}",shell=True).decode()
            mac_match=re.search(r"(([\dA-Fa-f]{2})[:-]{5}([\dA-Fa-f]){2})",output)
            mac=mac_match.group() if mac_match else None   
        except:
            mac=None
    return mac.lower() if mac else "Mac Not Found"

def get_mac_vendor(mac):
    if mac in mac_cache:
        return mac_cache[mac]
    try:
        vendor = MacLookup.lookup(mac)
        mac_cache[mac]=vendor
        with open(CACHE_FILE,"w") as f:
            json.dump(mac_cache,f)
        return vendor
    except:
        return "Unknown Vendor"
    
def os_detection(host_info,vendor,open_port,mac_address=""):
    guesses = []
    os_score = {}
    fall_back=None
    
    for match in host_info.get('osmatch',[]):
        name = match.get('name','Unknown')
        accuracy = int(match.get('accuracy',0))
        if accuracy>=90:
            guesses.append(f"{name} Acc: {accuracy}% ")
            os_score[name]=accuracy
        elif not fall_back:
            fall_back = f"{name} Acc: {accuracy}%"
            
        port_map={
            22 : "Linux/Unix (SSH)",
            445 : "Windows (SMB)",
            3389 : "Windows (RDP)",
            5555 : "Andriod (ADB)",
            62078 : "Apple (AFP)",
            3306 : "MySQL (Linux likely)",
            548: "macOS (AFP)",
            23: "Embedded (Telnet)",
            37215: "Huawei IoT", 
        }
        
        port_based_guess = [port_map[p] for p in open_port if p in port_map]
        
        v = vendor.lower()
        vendor_guess=""
        if any(x in v for x in [
            "Samsung", "Xiaomi", "Redmi", "OnePlus", "Realme", "Vivo", "Oppo", "Motorola", "Nokia", "Google", "Huawei",
            "Lenovo", "Sony", "LG", "Infinix", "Tecno", "Micromax", "Asus", "Honor", "Meizu", "ZTE", "Coolpad", "Lava", "Itel", "Panasonic", "Sharp", "Alcatel", "BLU", "LeEco"]):
            vendor_guess="Android"
        elif any(x in v for x in ["apple", "foxconn", "hon hai", "pegatron", "quanta", "compal", "luxshare", "wistron", "inventec"]):
            vendor_guess = "iOS / Apple Device"
    
        elif any(x in v for x in [
            "intel", "hp", "hewlett", "dell", "lenovo", "asus", "acer", "msi", "toshiba",
            "gigabyte", "samsung", "lg", "sony", "panasonic", "fujitsu", "vaio", "clevo"
        ]):
            vendor_guess = "Windows / PC / Laptop"

        elif any(x in v for x in [
            "raspberry", "arduino", "espressif", "beaglebone", "pine64", "banana", "orangepi",
            "hardkernel", "nvidia", "jetson", "seeed", "odroid", "olimex", "libre"
        ]):
            vendor_guess = "Linux (IoT / Embedded)"

        elif any(x in v for x in [
            "hikvision", "dahua", "axis", "uniview", "reolink", "ezviz", "cp plus", "honeywell",
            "swann", "flir", "bosch", "lorex", "panasonic", "geovision", "acti", "avtech", "mobotix"
        ]):
            vendor_guess = "CCTV Camera / Surveillance"

        elif any(x in v for x in [
            "tplink", "netgear", "dlink", "zyxel", "mikrotik", "cisco", "asus", "linksys", "huawei",
            "ubiquiti", "mercusys", "tenda", "edimax", "juniper", "hpe", "fortinet", "draytek", "openwrt"
        ]):
            vendor_guess = "Router / Modem / Network Device"

        mac_guess = ""
        if mac_address :
            oui=vendor.upper().replace(':',"")[:6]
            # === Raspberry Pi (Broadcom chipsets) ===
            if oui in ["B827EB", "DCA632", "E45F01", "DC446D", "D8D43C"]:
                mac_guess = "Raspberry Pi"

            # === VMware ===
            elif oui in ["000C29", "000569", "001C14", "005056", "00E04C"]:
                mac_guess = "VMware Virtual Machine"

            # === VirtualBox ===
            elif oui in ["080027"]:
                mac_guess = "VirtualBox Guest"

            # === Microsoft Hyper-V ===
            elif oui in ["00155D"]:
                mac_guess = "Hyper-V Virtual Machine"

            # === Parallels Desktop ===
            elif oui in ["001C42"]:
                mac_guess = "Parallels VM"

            # === QEMU / KVM ===
            elif oui in ["525400"]:
                mac_guess = "QEMU/KVM Virtual NIC"

            # === Xen (Amazon EC2 instances) ===
            elif oui in ["FECACA"]:
                mac_guess = "Xen Virtual Machine"

            # === IP Cameras ===
            elif oui in ["FCFC48", "2CF0A2", "886B0F"]:  
                mac_guess = "CCTV / IP Camera"

            # === Cisco Devices ===
            elif oui in ["00000C", "002264", "D4C9EF"]:
                mac_guess = "Cisco Network Device"

            # === TP-Link ===
            elif oui in ["30B5C2", "50C7BF", "84D6D0"]:
                mac_guess = "TP-Link Router/Switch"

            # === Ubiquiti ===
            elif oui in ["44D9E7", "782BCB", "DC9FDB"]:
                mac_guess = "Ubiquiti Device"

            # === MikroTik ===
            elif oui in ["4C5E0C", "6C3B6B", "D4CA6D"]:
                mac_guess = "MikroTik Router"

            # === Apple Devices ===
            elif oui in ["F8E903", "28F10E", "A4B1C1", "B827EB"]:
                mac_guess = "Apple Device"

            # === Samsung Android ===
            elif oui in ["F8E968", "84C9B2", "70F11C"]:
                mac_guess = "Samsung Android Device"

            # === Huawei Devices ===
            elif oui in ["38F23E", "F8D0BD", "001E10"]:
                mac_guess = "Huawei Device"

            # === Xiaomi Devices ===
            elif oui in ["7427EA", "18C086", "48EE0C"]:
                mac_guess = "Xiaomi Android Device"

    final_os_guess = "\n".join(guesses[:2]) if guesses else "Unknown OS Detection"
    
    if port_based_guess :
        final_os_guess += "\nPort Fingerprinting :" + ",".join(set(port_based_guess))
    if vendor_guess and vendor_guess not in final_os_guess :
        final_os_guess += f"\nVendor Heuristic : {vendor_guess}"
    if mac_guess and mac_guess not in final_os_guess :
        final_os_guess += f"\nMac Prefix guess : {mac_guess}"
        
    return final_os_guess

def suggest_exploit(service_str):
    base = {
    "ftp":"Brute-force / CVE-2024-4040 (CrushFTP zero-day), CVE-2024-7264 (Cerberus FTP cURL), CVE-2021-41653 (vsftpd backdoor)",
    "ssh":"CVE-2024-6387 (OpenSSH regreSSHion RCE) :contentReference[oaicite:1]{index=1}, CVE-2023-48795 (Terrapin), CVE-2024-3544 (SFTPGo bypass), CVE-2018-15473 (User enum)",
    "telnet":"Default creds / CVE-2015-5600 (OpenSSH KI-bypass), watch for legacy IoT exposures",
    "http":"CVE-2024-40725 (Apache source disclosure), CVE-2024-40898 (Windows SSRF), CVE-2021-5638 (Apache Struts RCE), CORS/HSTS misconfiguration :contentReference[oaicite:2]{index=2}",
    "https":"CVE-2022-0778 (OpenSSL DOS), TLS downgrade, CVE-2024-38472 (Windows UNC SSRF) :contentReference[oaicite:3]{index=3}",
    "apache":"CVE-2024-40725 (source disclosure), CVE-2024-40898 (SSRF) :contentReference[oaicite:4]{index=4}",
    "nginx":"CVE-2021-23017 (resolver heap overflow), CVE-2013-2028 (chunked overflow)",
    "smb":"MS17-010 (EternalBlue), CVE-2020-0796 (SMBGhost), CVE-2021-36942 (PrintNightmare)",
    "mysql":"CVE-2012-2122 (Auth bypass), CVE-2021-27928 (Config injection), default 'root' login",
    "mssql":"CVE-2022-35829 (SQL Server privilege misuse), brute-force, xp_cmdshell RCE",
    "rdp":"CVE-2019-0708 (BlueKeep), CVE-2020-0609/0610 (Gateway RCE)",
    "vnc":"Weak creds / CVE-2022-24990 (unauth access)",
    "exchange":"ProxyLogon CVE-2021-26855, ProxyShell CVE-2021-34473",
    "spring":"CVE-2022-22965 (Spring4Shell RCE)",
    "ssh-service":"CVE-2024-6387 (OpenSSH RCE) :contentReference[oaicite:5]{index=5}",
    "dahua":"CVE-2017-7921 (backdoor creds)",
    "hikvision":"CVE-2021-36260 (command injection)",
    "fortinet":"CVE-2018-13379 (Path traversal)",
    "sonicwall":"CVE-2021-20016 (SSLVPN SQLi)",
    "vpn":"CVE-2023-46805 & CVE-2024-21887 (Ivanti VPN chain) :contentReference[oaicite:6]{index=6}, CVE-2019-11510 (Pulse), CVE-2018-13379 (Fortinet)",
    "cisco":"CVE-2020-3452 (Path traversal), CVE-2020-3187 (conf overwrite), CVE-2019-15271 (RCE)",
    "wordpress":"CVE-2022-21661 (object injection), XML-RPC brute, vulnerable plugins/themes",
    "drupal":"CVE-2018-7600 (Drupalgeddon2), CVE-2019-6340 (RCE)",
    "joomla":"CVE-2015-8562 (User-Agent RCE), CVE-2019-18674 (SQLi)",
    "git":"CVE-2018-11235 (path traversal), CVE-2022-24765 (repo config), exposed .git",
    "redis":"Unauth RCE (cron/ssh), CVE-2022-0543 (Lua sandbox)",
    "elasticsearch":"CVE-2015-1427 (Groovy RCE), unauthorized access",
    "kibana":"CVE-2019-7609 (RCE), CVE-2021-22132 (file write)",
    "roundcube":"CVE-2024-42009 (XSS in show.php) :contentReference[oaicite:7]{index=7}",
    "crushftp":"CVE-2024-4040 (VFS bypass RCE) :contentReference[oaicite:8]{index=8}"
        
    }
    out = [v for k,v in base.items() if k in service_str.lower()]
    try:
        ss=subprocess.getoutput(f"searchsploit {service_str}").splitlines()
        cves=[line for line in ss if 'CVE' in line][:3]
        out.extend(cves)
    except:
        pass
    
    return out or ["No CVE match found"]

def detect_anomaly(port : list,services : list)->str:
    alert = []
    port_set=set(port)
    services_str = "".join(services).lower()
    
    def add_alert(msg,severity="Medium",category="General",Mitre="T1595",cve="N/A"):
        alert.append(f"[{severity} {msg} - {category} | Mitre : {Mitre} | CVE : {cve}]")
        
    known_vuln_services ={
        "apache/2.4.49": ("Apache 2.4.49 — Path Traversal RCE", "Critical", "RCE", "T1190", "CVE-2021-41773"),
        "jenkins": ("Jenkins dashboard exposed — Unauth RCE (Script Console)", "High", "RCE/Admin Exposure", "T1068", "CVE-2018-1000861"),
        "grafana": ("Grafana unauth dashboard — CVE-2021-43798 LFI", "High", "Info Leak/RCE", "T1040", "CVE-2021-43798"),
        "openssh_7.2": ("OpenSSH 7.2 — vulnerable to downgrade/enum", "Medium", "Auth Bypass", "T1110", "CVE-2016-10012"),
        "mysql 5.5": ("MySQL 5.5 — EOL, known exploits", "High", "Data Leak/Auth Bypass", "T1078", "Multiple CVEs"),
        "confluence/7.13": ("Atlassian Confluence — CVE-2022-26134 OGNL Injection RCE", "Critical", "RCE", "T1190", "CVE-2022-26134"),
        "gitlab": ("GitLab unauth RCE — CVE-2021-22205", "High", "Remote Code Execution", "T1059", "CVE-2021-22205"),
        "exchange": ("Microsoft Exchange — ProxyShell Exploit Chain", "Critical", "Remote Code Execution", "T1190", "CVE-2021-34473"),
        "fortinet/fortigate": ("FortiOS SSL VPN — CVE-2023-27997 Pre-auth RCE", "Critical", "Remote Code Execution", "T1190", "CVE-2023-27997"),
        "goanywhere": ("GoAnywhere MFT — CVE-2023-0669 Auth Bypass", "Critical", "Initial Access", "T1190", "CVE-2023-0669"),
        "moveit": ("MOVEit Transfer — CVE-2023-34362 SQLi to RCE", "Critical", "Data Exfiltration", "T1071", "CVE-2023-34362"),
        "teamcity": ("JetBrains TeamCity — CVE-2023-42793 Unauth RCE", "Critical", "RCE", "T1210", "CVE-2023-42793"),
    }
    for k,v in known_vuln_services.items():
        if k in services_str:
            add_alert(*v) 
            
    # === 2. Port Risk Fingerprinting
    dangerous_ports = {
        "23/tcp": ("Telnet open — unencrypted and obsolete", "High", "Remote Access Misuse", "T1021", "N/A"),
        "21/tcp": ("FTP open — try anonymous login, sniff plain creds", "High", "Credential Theft", "T1040", "N/A"),
        "445/tcp": ("SMB exposed — EternalBlue vector", "Critical", "Lateral Movement", "T1021.002", "CVE-2017-0144"),
        "3389/tcp": ("RDP open — ransomware lateral entry point", "Critical", "Lateral Movement", "T1021.001", "CVE-2019-0708"),
        "6379/tcp": ("Redis open — RCE possible via config write", "High", "Remote Exploitation", "T1210", "Multiple"),
        "9200/tcp": ("Elasticsearch open — CVE-2015-1427 RCE", "High", "Data Leak/RCE", "T1210", "CVE-2015-1427"),
        "8009/tcp": ("AJP open — Ghostcat CVE-2020-1938 RCE via Tomcat", "High", "Remote Exploitation", "T1210", "CVE-2020-1938"),
        "5000/tcp": ("Docker API open — unauth access to containers", "High", "Container Abuse", "T1611", "N/A"),
        "7001/tcp": ("WebLogic exposed — CVE-2020-14882/3 chain RCE", "Critical", "Remote Exploitation", "T1190", "Multiple CVEs"),
        "9201/tcp": ("Elasticsearch cluster exposed — info leak or RCE", "High", "Data Exposure", "T1213", "N/A"),
        "4505/tcp": ("SaltStack Master exposed — CVE-2020-11651/52 RCE", "High", "Remote Exploitation", "T1210", "CVE-2020-11651"),
        "80/tcp": ("HTTP open — test for exposed admin panels", "Medium", "Recon Surface", "T1595", "N/A"),
    }
    for  port,details in dangerous_ports.items():
        if port in port_set:
            add_alert(*details)
            
    # === 3. Insecure Combinations
    if {"445/tcp", "3389/tcp"}.issubset(port_set):
        add_alert("SMB + RDP combo — ransomware kill chain vector", "Critical", "Lateral Movement", "T1569", "Multiple")

    if {"80/tcp", "443/tcp"}.intersection(port_set):
        if not any(x in services_str for x in ["hsts", "csp", "cors"]):
            add_alert("Web exposed — missing security headers", "Medium", "Web App Misconfig", "T1189", "N/A")

    if "phpmyadmin" in services_str:
        add_alert("phpMyAdmin exposed — try default creds", "High", "Admin Panel Exposure", "T1078", "Multiple")
        
    if {"22/tcp", "5000/tcp"}.issubset(port_set):
        add_alert("SSH + Docker API combo — host/container lateral movement", "Critical", "Pivoting Risk", "T1610", "N/A")

    if {"80/tcp", "9200/tcp"}.issubset(port_set):
        add_alert("Web + Elasticsearch — often misconfigured, data exfil path", "High", "Recon/Leak Risk", "T1213", "N/A")

    if "grafana" in services_str and {"3000/tcp", "9090/tcp"}.issubset(port_set):
        add_alert("Grafana + Prometheus combo — telemetry leak vector", "Medium", "Observability Exploitation", "T1082", "N/A")

     # === 4. Pattern-Based Risk Detection
    weak_patterns = [
        (r"nginx/1\.1[02]", "Old NGINX version — HTTP2 flaws"),
        (r"apache/2\.2", "Apache 2.2 — legacy, vulnerable to multiple RCEs"),
        (r"php/5\.6", "PHP 5.6 — end-of-life, known RCEs"),
        (r"tomcat/7\.", "Tomcat 7 — multiple deserialization/RCE bugs"),
        (r"drupal/[78]", "Drupal 7/8 — CVE-2018-7600 'Drupalgeddon2' RCE"),
        (r"wordpress", "WordPress detected — check for XMLRPC, plugin RCE"),
        (r"python/2\.7", "Python 2.7 — EOL version, vulnerable to many RCEs"),
        (r"jboss", "JBoss detected — CVE-2017-12149 deserialization RCE"),
    ]
    for pattern,msg in weak_patterns:
        if re.search(pattern,services_str):
            add_alert(msg,"High","Software Vulnerabiliy","T1203","Multiple")
            
    
     # === 5. Default Creds
    default_creds = [
        ("grafana", "Grafana default creds (admin/admin)"),
        ("minio", "MinIO default creds (minioadmin:minioadmin)"),
        ("zabbix", "Zabbix default creds (Admin/zabbix)"),
        ("kibana", "Kibana default creds (elastic:changeme)"),
        ("rabbitmq", "RabbitMQ default creds (guest:guest)"),
        ("mosquitto", "MQTT Broker open — no auth, IoT control risk"),
        ("nifi", "Apache NiFi default creds (nifi:nifi123)"),
        ("tomcat", "Tomcat Manager default creds (tomcat:tomcat)"),
    ]
    for key, msg in default_creds:
        if key in services_str:
            add_alert(msg, "High", "Credential Exposure", "T1078", "N/A")
            
    # === 6. Heuristic AI-like Anomaly
    if "dropbear" in services_str:
        add_alert("Dropbear SSH — used in IoT, often no auth", "High", "IoT Exposure", "T1021", "Multiple")

    if re.search(r"(root|admin).*mysql", services_str):
        add_alert("MySQL running as root — privilege escalation vector", "High", "Priv Esc", "T1068", "N/A")
    
    if re.search(r"(solr|couchdb).*unauth", services_str):
        add_alert("DB exposed without auth — CVE-style NoSQL exploit vector", "High", "Data Exposure", "T1213", "Multiple")

    if "aws_access_key" in services_str or "aws_secret" in services_str:
        add_alert("AWS credentials exposed in service banners", "Critical", "Cloud Key Leak", "T1552.001", "N/A")

    if re.search(r"(root|admin).*mongo", services_str):
        add_alert("MongoDB running as root/admin — privilege abuse path", "High", "Priv Esc", "T1068", "N/A")

    if "celery" in services_str and "flower" in services_str:
        add_alert("Celery Flower dashboard — check for remote task execution", "High", "Task Abuse", "T1059", "N/A")
        
    # === 7. IoT/Cloud Ports
    if "7547/tcp" in port:
        add_alert("TR-069 port open — exploited by Mirai botnet", "Critical", "IoT Infection", "T1043", "Multiple")

    if "554/tcp" in port and "rtsp" in services_str:
        add_alert("RTSP stream exposed — CCTV/IP camera unauth risk", "High", "Surveillance Leak", "T1123", "N/A")
    
    if "5985/tcp" in port:
        add_alert("WinRM (5985) open — used in remote PowerShell", "High", "Remote Admin Abuse", "T1021.006", "N/A")

    if "2375/tcp" in port:
        add_alert("Docker daemon open — CVE-2019-5736 container breakout risk", "Critical", "Container Breakout", "T1611", "CVE-2019-5736")

    if "8443/tcp" in port and "vcenter" in services_str:
        add_alert("vCenter port open — check for CVE-2021-21972 unauth RCE", "Critical", "Virtual Infra Access", "T1021.006", "CVE-2021-21972")

    if "10250/tcp" in port and "kubelet" in services_str:
        add_alert("Kubernetes Kubelet open — possible RCE or metrics leak", "High", "Cluster Control Risk", "T1610", "Multiple")

    if "1900/udp" in port:
        add_alert("SSDP open — DDoS reflector or IoT scanner vector", "Medium", "DDoS Vector", "T1499", "N/A")
        
    if not alert:
        alert.append("[OK] No immediate anomaly detected , recommend manual review")
        
    return "\n".join(alert)
    
    
def scan_target(ip,mode='tcp',aggressive=True):
    scanner = nmap.PortScanner()

    args = {
        'tcp': "-T4 -O -sV --top-ports 1000 --script vulners",
        'udp': "-T4 -sU --top-ports 50",
        'both': "-T4 -O -sS -sU --top-ports 50 --script vulners"
    }.get(mode, "-T4 -O -sV --top-ports 1000 --script vulners")

    if aggressive:
        args += " -A"

    try:
        scanner.scan(ip, arguments=args + " --host-timeout 60s")

        if ip not in scanner.all_hosts():
            scanner.scan(ip, arguments="-Pn -T4")
    except:
        return [ip, "Unresponsive"]
    
    info = scanner[ip]
    mac = get_mac(ip)
    vendor = get_mac_vendor(mac) if mac != "MAC Not Found" else "Unknown"
    ports,services,exploit=[],[],[]
    open_port_nums = []  

    for proto in ('tcp', 'udp'):
        if proto in info:
            for port in info[proto]:
                pdata = info[proto][port]
                port_str = f"{port}/{proto} ({pdata['state']})"
                ports.append(port_str)
                open_port_nums.append(port)
                
                sdecs = f"{pdata.get('name','')} {pdata.get('product','')} { pdata.get('version','')}".strip()
                if sdecs:
                    services.append(f"{port}/{proto}:{sdecs}")
                    exploit+=suggest_exploit(sdecs)
    
    exploit_str="".join(set(exploit))
    os = os_detection(info, vendor, open_port_nums, mac_address=mac)
    port_str=",".join(ports)
    alert = detect_anomaly(port_str,services)
    
    return os,exploit_str,services,alert
        
def main():
    printBanner()
    test_ip = console.input("[green]Enter IP : [/green]")
    mode = console.input("[yellow]Scan mode : [/yellow]")
    
    os, exploit, services, alert = scan_target(test_ip, mode, 1)

    console.print(f"[blue]Detected OS:\n{os}[/blue]")
    console.print(f"[bright_yellow]Exploit Suggestion:\n{exploit}[/bright_yellow]")
    console.print(f"[cyan]Services:\n{services}[/cyan]")
    console.print(f"[bold red]Alerts:\n{alert}[/bold red]")

    
if __name__== "__main__":
    main()