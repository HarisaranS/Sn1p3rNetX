import os
import nmap
import ipaddress
import netifaces
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.parser import parse_nmap_info
from core.utils import log_message

def is_root():
    return os.getuid() == 0

def scan_target(ip, mode='tcp', aggressive=False):
    scanner = nmap.PortScanner()
    args = {'tcp': "-T4 -O -sV --top-ports 1000", 'udp': "-T4 -sU --top-ports 50", 'both': "-T4 -O -sS -sU --top-ports 50"}.get(mode, "-T4 -O -sV --top-ports 1000")
    
    if not is_root():
        # Remove OS detection if not root to avoid crash
        args = args.replace("-O", "").replace("-sS", "-sT")
        
    if aggressive: 
        args += " -A"
        
    try:
        scanner.scan(ip, arguments=args + " --host-timeout 60s")
        if ip not in scanner.all_hosts():
            scanner.scan(ip, arguments="-Pn -T4")
            if ip not in scanner.all_hosts():
                return {"ip": ip, "status": "Unresponsive", "error": "Host seems down."}
            else:
                status = "Firewalled but Live"
        else:
            status = "Live"
            
        info = scanner[ip]
        parsed_data = parse_nmap_info(ip, info)
        parsed_data['status'] = status
        return parsed_data
        
    except Exception as e:
        log_message(f"[!] Error scanning {ip}: {e}")
        return {"ip": ip, "status": "Error", "error": str(e)}

def discover_hosts(target_range):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target_range, arguments="-T4 -sn")
        return scanner.all_hosts()
    except Exception as e:
        log_message(f"Discovery error on {target_range}: {e}")
        return []

def scan_network_range(target_range, mode='tcp', aggressive=False, threads=20, callback=None):
    if target_range.lower() == 'auto':
        try:
            default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            iface_info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
            local_ip = iface_info['addr']
            netmask = iface_info['netmask']
            interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
            target_range = str(interface.network)
        except Exception as e:
            return {"error": f"Auto detection failed: {e}", "results": []}
            
    try:
        net = ipaddress.ip_network(target_range, strict=False)
    except Exception as e:
        return {"error": "Invalid CIDR notation or IP address.", "results": []}

    if net.num_addresses == 1:
        # Single IP
        live_hosts = [str(net.network_address)]
    else:
        # Subnet
        if callback: callback(f"Discovering live hosts in {target_range}...")
        live_hosts = discover_hosts(target_range)
        
    if not live_hosts:
        return {"error": "No live hosts detected.", "results": [], "target": target_range}
        
    results = []
    active_ips = set()
    
    def tracked_scan(ip):
        if callback:
            active_ips.add(ip)
            callback(f"Active Scans: {', '.join(sorted(list(active_ips)))}")
        
        try:
            res = scan_target(ip, mode, aggressive)
            return res
        finally:
            if callback:
                active_ips.discard(ip)
                if active_ips:
                    callback(f"Active Scans: {', '.join(sorted(list(active_ips)))}")
                else:
                    callback("Processing results...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(tracked_scan, ip): ip for ip in live_hosts}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                pass
                
    return {"results": results, "target": target_range, "live_hosts_count": len(live_hosts)}
