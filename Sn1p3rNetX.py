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
    
def main():
    printBanner()
    log("[*] Sn1p3rNetX+ started!")
    test_ip = console.input("Enter IP : ")
    mac=get_mac(test_ip)
    vendor=get_mac_vendor(mac)
    console.print(f"[bold red]MAC Address:[/bold red] {mac}")
    console.print(f"[bold red]Vendor Name:[/bold red] {vendor}")
    log(f"Lookup done for {test_ip} -> Mac : {mac} , Vendor : {vendor}")
    
    
if __name__== "__main__":
    main()