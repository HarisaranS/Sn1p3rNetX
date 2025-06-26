import os, re, ipaddress, subprocess, json, csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup
from pyfiglet import Figlet
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import nmap

# === Setup ===
init(autoreset=True)
console = Console()
results_data = []
scanned_ips = set()
CACHE_FILE = ".mac_cache.json"
save_file = "results.json"
log_file = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
mac_cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE,"r") as f:
        mac_cache=json.load(f)

def print_Banner():
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
            
    final_os_guess = "\n".join(guesses[:2]) if guesses else "Unknown OS Detection"


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
    
    return out 

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
            if ip not in scanner.all_hosts():
                return [ip, "Unresponsive", "-", "-", "-", "-", "-", "-", "-"]
            else:
                status = "Firewalled but Live"
        else:
            status = "Live"
    
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
        
        os = os_detection(info, vendor, open_port_nums, mac_address=mac) \
            if 'osmatch' in  info or 'tcp' in info else "OS detection Skipped"
            
        port_str=",".join(ports)
        
        vuln_output = "\n".join([
            script.get('output','') for script in info.get('Hostname','') \
                if 'vulners' in script.get('id','')
        ])
        
        alert = detect_anomaly(port_str,services)

        result = [ip, status, mac, vendor, os, port_str, vuln_output or "None", exploit_str, alert]

        results_data.append({
                "IP": ip,
                "Status": status,
                "MAC": mac,
                "Vendor": vendor,
                "OS": os,
                "Ports": port_str,
                "Vulnerabilities": vuln_output or "None",
                "Exploits": exploit_str or "No CVE match found",
                "Alert": alert,
            })

        return result

    except Exception as e:
        log(f"[!] Error scanning {ip}: {e}")
        return [ip, "Error", "Error", "Error", "Error", "Error", "Error", "Error", str(e)]
        
def scan_network(target_range, mode='tcp', aggressive=False, threads=20, fresh=False):
    if fresh and os.path.exists(save_file): os.remove(save_file)
    try:
        if target_range.lower() == 'auto':
            default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            iface_info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
            local_ip = iface_info['addr']
            netmask = iface_info['netmask']
            interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
            target_range = str(interface.network)
            console.print(f"[yellow][+] Auto-detected local subnet: {target_range}[/yellow]")
        net = ipaddress.ip_network(target_range, strict=False)
        if net.prefixlen < 24:
            console.print(
                f"[bold red][!] Warning:[/bold red] You are scanning a large subnet ({target_range}). "
                "This may take a long time and consume high system/network resources. Proceeding anyway..."
            )
    except:
        console.print("[red][-] Invalid CIDR notation.[/red]")
        return
    scanner = nmap.PortScanner()
    console.print(f"[yellow]\n[+] Performing ping scan on: {target_range}[/yellow]")
    scanner.scan(hosts=target_range, arguments="-T4 -sn")
    live_hosts = scanner.all_hosts()
    if not live_hosts:
        console.print("[-] No live hosts detected", style="red")
        return
    console.print(f"[green][+] {len(live_hosts)} live hosts found. Starting deep scan...\n")
    with Progress() as progress:
        task = progress.add_task("[bold blue]Scanning Hosts...", total=len(live_hosts))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_target, ip, mode, aggressive): ip for ip in live_hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    console.print(f"[cyan]{ip}[/cyan]: Scan Done → [green]{result[1]}[/green]")
                except Exception as e:
                    log(f"Error scanning {ip}: {e}")
                progress.update(task, advance=1)
    if results_data:
        with open("results.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results_data[0].keys())
            writer.writeheader()
            writer.writerows(results_data)
        with open(save_file, "w", encoding="utf-8") as jf:
            json.dump(results_data, jf, indent=4)
        table = Table(show_header=True, header_style="bold magenta")
        for col in results_data[0].keys():
            table.add_column(col, style="white", overflow="fold")
        for r in results_data:
            table.add_row(*[str(r[col]) for col in r])
        console.print("\n[green][+] Scan Results:[/green]\n")
        console.print(table)

def interactive_mode():
    print_Banner()
    console.print("[bold blue]Interactive Mode (Beginner-Friendly)[/bold blue]")
    target = console.input("[green]Enter Target CIDR or type 'auto': [/green]")
    mode = console.input("[green]Scan Mode? [tcp/udp/both] (default: tcp): [/green]") or "tcp"
    aggressive = console.input("[green]Aggressive Scan? [y/n] (default: n): [/green]").lower() == 'y'
    threads = console.input("[green]Max Threads? (default: 20): [/green]")
    fresh = console.input("[green]Fresh Scan? [y/n] (default: n): [/green]").lower() == 'y'
    try: threads = int(threads)
    except: threads = 20
    scan_network(target, mode, aggressive, threads, fresh)


def main():
        interactive_mode()

if __name__ == "__main__":
    main()
