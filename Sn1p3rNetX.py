import argparse, os, sys, re, netifaces, ipaddress, subprocess, json, csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup
from pyfiglet import Figlet
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import joblib
import nmap

init(autoreset=True)
console = Console()
results_data = []
scanned_ips = set()
CACHE_FILE = ".mac_cache.json"
save_file = "results.json"
log_file = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
mac_cache = {}

# === Load AI Model ===
try:
    ai_model = joblib.load("ai_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
except:
    ai_model = None
    vectorizer = None

# === Helpers ===
def print_banner():
    f = Figlet(font='slant')
    console.print(f.renderText('Sn1p3rNetX+'), style="bold green")
    console.print("[bold cyan]\tNetwork Reconnaissance with AI + Heuristics[/bold cyan]")
    console.print("\t\t[bold red]>>>  by  $3r3N  <<<[/bold red]\n")

def log(msg):
    os.makedirs("logs", exist_ok=True)
    with open(log_file, "a") as logf:
        logf.write(msg + "\n")

def get_mac(ip):
    mac = get_mac_address(ip=ip)
    if not mac:
        try:
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
            mac_match = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", output)
            mac = mac_match.group(0) if mac_match else None
        except:
            mac = None
    return mac.lower() if mac else "MAC Not Found"

def get_mac_vendor(mac):
    if mac in mac_cache:
        return mac_cache[mac]
    try:
        vendor = MacLookup().lookup(mac)
        mac_cache[mac] = vendor
        with open(CACHE_FILE, "w") as f:
            json.dump(mac_cache, f)
        return vendor
    except:
        return "Unknown Vendor"

def smart_os_detection(host_info, vendor, open_ports, mac_address=""):
    guesses = []
    fallback = None
    for match in host_info.get('osmatch', []):
        name = match.get('name', 'Unknown')
        accuracy = int(match.get('accuracy', 0))
        if accuracy >= 90:
            guesses.append(f"{name} (Acc: {accuracy}%)")
        elif not fallback:
            fallback = f"{name} (Acc: {accuracy}%)"
    if not guesses and fallback:
        guesses.append(fallback)
    return "\n".join(guesses[:2]) if guesses else "OS Detection Uncertain"

def suggest_exploits(service_str):
    known = [
        # === Web servers ===
        ("apache", "CVE-2024-40725 (Apache Source Disclosure)"),
        ("apache/2.4.49", "CVE-2021-41773 (Path Traversal RCE)"),
        ("nginx", "CVE-2022-41741 (Memory leak via header manipulation)"),
        ("tomcat", "CVE-2020-1938 (Ghostcat AJP RCE)"),

        # === SSH & FTP ===
        ("openssh", "CVE-2024-6387 (OpenSSH RCE - Signal handler race)"),
        ("dropbear", "IoT SSH - weak auth vector"),
        ("vsftpd", "CVE-2011-2523 (Backdoor exploit)"),

        # === SMB & RDP ===
        ("smb", "MS17-010 (EternalBlue RCE)"),
        ("rdp", "CVE-2019-0708 (BlueKeep RCE)"),

        # === Databases ===
        ("mysql", "Weak root login / CVE-2022-31626"),
        ("mongodb", "CVE-2017-15535 (No auth exposure)"),
        ("redis", "Config write RCE / CVE-2022-0543"),

        # === Docker/K8s ===
        ("docker", "CVE-2019-5736 (Container breakout)"),
        ("kubelet", "CVE-2018-1002105 (API bypass)"),
        ("etcd", "Unauth open cluster - full data exposure"),

        # === Monitoring / DevOps ===
        ("grafana", "CVE-2021-43798 (LFI unauth dashboard)"),
        ("prometheus", "No auth metrics leak"),
        ("jenkins", "CVE-2018-1000861 (Script console RCE)"),
        ("nexus", "CVE-2020-10204 (Repo upload bypass)"),

        # === Messaging & IoT ===
        ("rabbitmq", "Default creds dashboard CVE-2021-32719"),
        ("mqtt", "Unauth MQTT broker (no creds)"),
        ("tr-069", "CVE-2017-17215 (Mirai exploit vector)"),

        # === Remote Admin / Misc ===
        ("winrm", "Exposed PowerShell abuse (5985/tcp)"),
        ("weblogic", "CVE-2020-2551 / CVE-2020-14882 (Admin RCE)"),
        ("jupyter", "No auth notebook RCE"),
        ("phpmyadmin", "Default creds & RCE via db injection"),
        ("kibana", "CVE-2021-22132 (Prototype pollution)"),

        # === Weak Exposed Interfaces ===
        ("vnc", "Open VNC - no auth RFB protocol"),
        ("webcam", "Open MJPEG stream - no login"),
        ("rtsp", "IP camera stream unauth access"),
        
        ("fortinet", "CVE-2023-27997 (SSL VPN Pre-auth RCE)"),
        ("pulse", "CVE-2019-11510 (Arbitrary File Read)"),
        ("citrix", "CVE-2019-19781 (Directory Traversal RCE)"),
        
        ("exchange", "ProxyShell Chain CVE-2021-34473, CVE-2021-34523"),
        ("iis", "CVE-2021-41379 (IIS privilege escalation)"),
        ("outlook", "CVE-2023-23397 (Credential theft via calendar)"),

        ("teamcity", "CVE-2023-42793 (Unauth RCE)"),
        ("gitlab", "CVE-2021-22205 (Image parsing RCE)"),
        ("goanywhere", "CVE-2023-0669 (Auth Bypass RCE)"),

        ("modbus", "Unauth modbus/TCP — critical ICS exposure"),
        ("opc", "OPC-UA open port — vulnerable to replay/data theft"),

        ("metadata.google.internal", "CVE-2020-1350 (SSRF → Cloud creds)"),
        ("aws_access_key", "Cloud Key Leak — critical cloud exposure"), 
    ]
    found = [v for k, v in known if k in service_str.lower()]
    try:
        ss = subprocess.getoutput(f"searchsploit {service_str}").splitlines()
        cves = [line for line in ss if "CVE" in line][:3]
        found.extend(cves)
    except:
        pass
    return found

def ai_detect_anomaly(ports, services):
    if not ai_model or not vectorizer:
        return "[AI] Model not loaded"
    sample = " ".join(ports + services).lower()
    vec = vectorizer.transform([sample])
    pred = ai_model.predict(vec)
    return "[AI] Potential anomaly detected" if pred[0] == -1 else "[AI] Looks normal"

def scan_target(ip, mode='tcp', aggressive=False):
    if ip in scanned_ips:
        return [ip, "Skipped", "Already Scanned", "-", "-", "-", "-", "-", "-"]
    scanned_ips.add(ip)
    scanner = nmap.PortScanner()
    args = {'tcp': "-T4 -O -sV --top-ports 1000", 'udp': "-T4 -sU --top-ports 50", 'both': "-T4 -O -sS -sU --top-ports 50"}.get(mode, "-T4 -O -sV --top-ports 1000")
    if aggressive: args += " -A"
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
        vendor = get_mac_vendor(mac)
        ports, services, exploits = [], [], []
        open_port_nums = []
        for proto in ('tcp', 'udp'):
            if proto in info:
                for port in info[proto]:
                    pdata = info[proto][port]
                    ports.append(f"{port}/{proto}")
                    open_port_nums.append(port)
                    sdesc = f"{pdata.get('name','')} {pdata.get('product','')} {pdata.get('version','')}".strip()
                    if sdesc:
                        services.append(f"{port}/{proto}: {sdesc}")
                        exploits += suggest_exploits(sdesc)
        os = smart_os_detection(info, vendor, open_port_nums, mac)
        alert = ai_detect_anomaly(ports, services)
        result = [ip, status, mac, vendor, os, ", ".join(ports), "\n".join(services), "\n".join(set(exploits)) or "None", alert]
        results_data.append({"IP": ip,
                             "Status": status,
                             "MAC": mac,
                             "Vendor": vendor,
                             "OS": os, "Ports": ", ".join(ports),
                             "Services": "\n".join(services),
                             "Exploits": "\n".join(set(exploits)),
                             "Alert": alert
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
    print_banner()
    console.print("[bold blue]Interactive Mode (Beginner-Friendly)[/bold blue]")
    target = console.input("[green]Enter Target CIDR or type 'auto': [/green]")
    mode = console.input("[green]Scan Mode? [tcp/udp/both] (default: tcp): [/green]") or "tcp"
    aggressive = console.input("[green]Aggressive Scan? [y/n] (default: n): [/green]").lower() == 'y'
    threads = console.input("[green]Max Threads? (default: 20): [/green]")
    fresh = console.input("[green]Fresh Scan? [y/n] (default: n): [/green]").lower() == 'y'
    try: threads = int(threads)
    except: threads = 20
    scan_network(target, mode, aggressive, threads, fresh)

def cli_mode():
    parser = argparse.ArgumentParser(description="Sn1p3rNetX+ - Enhanced Recon Tool")
    parser.add_argument("--target", help="Target CIDR or 'auto'", required=True)
    parser.add_argument("--mode", choices=['tcp', 'udp', 'both'], default="tcp")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()
    print_banner()
    scan_network(args.target, args.mode, args.aggressive, args.threads, args.fresh)

def main():
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
