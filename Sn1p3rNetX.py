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
    return os,exploit_str,services
        
def main():
    printBanner()
    log("[*] Sn1p3rNetX+ started!")
    test_ip = console.input("Enter IP : ")
    mode=input("Enter a mode :")
    os,exploit,services = scan_target(test_ip,mode,1)
    print(os)
    print(f"Exploit suggestion : {exploit}")
    print(f"Services : {services}")
    
    
if __name__== "__main__":
    main()