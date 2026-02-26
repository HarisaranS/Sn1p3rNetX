import re
import os
import subprocess
import netifaces
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup
import json

CACHE_FILE = ".mac_cache.json"
mac_cache = {}

def get_mac(ip):
    # Try to see if it's a local interface first
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if addr.get('addr') == ip:
                    # Found local interface, return its MAC (AF_LINK)
                    if netifaces.AF_LINK in addrs:
                        mac = addrs[netifaces.AF_LINK][0].get('addr')
                        if mac: return mac.lower()

    mac = get_mac_address(ip=ip)
    if not mac:
        try:
            output = subprocess.check_output(f"arp -a {ip}", shell=True, stderr=subprocess.DEVNULL).decode()
            mac_match = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", output)
            mac = mac_match.group(0) if mac_match else None
        except:
            mac = None
    return mac.lower() if mac else "MAC Not Found"

def get_mac_vendor(mac):
    global mac_cache
    if not mac_cache and os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                mac_cache = json.load(f)
        except:
            pass

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

def smart_os_detection(host_info):
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

def parse_nmap_info(ip, info):
    # Try to get mac from nmap results first (more reliable when root)
    mac = info.get('addresses', {}).get('mac')
    if mac:
        mac = mac.lower()
    else:
        mac = get_mac(ip)
        
    vendor = get_mac_vendor(mac)
    
    ports = []
    services = []
    open_port_nums = []
    
    for proto in ('tcp', 'udp'):
        if proto in info:
            for port in info[proto]:
                pdata = info[proto][port]
                state = pdata.get('state', '')
                if state != 'open' and state != 'open|filtered':
                    continue
                    
                ports.append(f"{port}/{proto}")
                open_port_nums.append(port)
                
                sdesc = f"{pdata.get('name','')} {pdata.get('product','')} {pdata.get('version','')}".strip()
                if sdesc:
                    services.append({"port": port, "protocol": proto, "description": sdesc, "name": pdata.get('name','')})
                    
    os_desc = smart_os_detection(info)
    
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "os": os_desc,
        "open_ports": ports,
        "services": services
    }
