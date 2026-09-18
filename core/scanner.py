import os
import nmap
import ipaddress
import netifaces
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.parser import parse_nmap_info
from core.utils import log_message


def is_root() -> bool:
    """Return True if the process is running as root (UID 0)."""
    return os.getuid() == 0


def _build_scan_args(mode: str, aggressive: bool, root: bool) -> str:
    """
    Construct nmap argument string based on mode, aggressiveness, and privilege.

    Non-root cannot use raw sockets, so we always fall back to:
      -sT  (TCP connect scan)  — works without root
      -sV  (service/version)   — works without root
    Root gains:
      -sS  (SYN stealth)
      -O   (OS detection)
    """
    base_args = "-T4 --host-timeout {timeout}s"

    if root:
        if mode == "udp":
            core = "-sU --top-ports 50"
        elif mode == "both":
            core = "-sS -sU -sV --top-ports 100"
        else:                         # default: tcp
            core = "-sS -sV -O --top-ports 1000"
    else:
        # Non-root: always use TCP connect so sockets work
        if mode == "udp":
            core = "-sT --top-ports 100"  # UDP requires root; fallback to TCP
        elif mode == "both":
            core = "-sT -sV --top-ports 100"
        else:
            core = "-sT -sV --top-ports 1000"

    if aggressive:
        core += " -A --script=banner,http-title,ssl-cert"

    return core


def scan_target(ip: str, mode: str = "tcp", aggressive: bool = False,
                timeout: int = 120) -> dict:
    """
    Scan a single host with nmap.  Returns a parsed dict; never raises.
    Includes a two-pass strategy: if the first pass finds the host up but
    with no ports (firewalled ping), a second pass with -Pn is attempted.
    """
    scanner = nmap.PortScanner()
    root = is_root()
    args = _build_scan_args(mode, aggressive, root).replace("{timeout}", str(timeout))

    try:
        scanner.scan(ip, arguments=args)

        if ip not in scanner.all_hosts():
            # Host didn't respond to ping probes — retry with -Pn (treat as up)
            log_message(f"Host {ip} not found in first pass — retrying with -Pn")
            pn_args = args + " -Pn"
            scanner.scan(ip, arguments=pn_args)

            if ip not in scanner.all_hosts():
                return {"ip": ip, "status": "Unresponsive", "error": "Host appears down."}
            status = "Firewalled / Live"
        else:
            status = "Live"

        host_info = scanner[ip]
        parsed = parse_nmap_info(ip, host_info)
        parsed["status"] = status

        # ── Second pass if we got 0 ports (could be ping-blocked) ─────────────
        if not parsed.get("open_ports") and status == "Live":
            log_message(f"Zero ports on first pass for {ip} — retrying with -Pn")
            pn_args = args + " -Pn"
            scanner.scan(ip, arguments=pn_args)
            if ip in scanner.all_hosts():
                parsed = parse_nmap_info(ip, scanner[ip])
                parsed["status"] = "Firewalled / Live"

        return parsed

    except nmap.PortScannerError as e:
        log_message(f"nmap error scanning {ip}: {e}", "error")
        return {"ip": ip, "status": "Error", "error": f"nmap: {e}"}
    except Exception as e:
        log_message(f"Unexpected error scanning {ip}: {e}", "error")
        return {"ip": ip, "status": "Error", "error": str(e)}


def discover_hosts(target_range: str) -> list:
    """
    Ping-sweep to find live hosts in a subnet.
    Falls back to -Pn discovery if sweep returns nothing.
    """
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target_range, arguments="-T4 -sn")
        found = scanner.all_hosts()
        if found:
            return found
        # Fallback: some networks block ICMP; try ARP-based (-PR) if root
        if is_root():
            scanner.scan(hosts=target_range, arguments="-T4 -sn -PR")
            return scanner.all_hosts()
        return []
    except Exception as e:
        log_message(f"Discovery error on {target_range}: {e}", "warning")
        return []


def scan_network_range(target_range: str, mode: str = "tcp", aggressive: bool = False,
                       threads: int = 20, timeout: int = 120,
                       callback=None) -> dict:
    """
    Main entry point — accepts a single IP, CIDR, hostname, or 'auto'.
    Returns: {"results": [...], "target": str, "live_hosts_count": int}
    """
    # ── auto-detect local subnet ───────────────────────────────────────────────
    if target_range.lower() == "auto":
        try:
            gws = netifaces.gateways()
            default_gw = gws["default"][netifaces.AF_INET]
            iface_info = netifaces.ifaddresses(default_gw[1])[netifaces.AF_INET][0]
            local_ip   = iface_info["addr"]
            netmask    = iface_info["netmask"]
            iface_net  = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
            target_range = str(iface_net.network)
            log_message(f"Auto-detected subnet: {target_range}")
        except Exception as e:
            return {"error": f"Auto-detection failed: {e}", "results": []}

    # ── validate / classify target ─────────────────────────────────────────────
    try:
        net = ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        # Might be a hostname — treat as single target
        net = None

    if net is not None and net.num_addresses == 1:
        live_hosts = [str(net.network_address)]
    elif net is not None:
        if callback:
            callback(f"Discovering live hosts in {target_range}…")
        live_hosts = discover_hosts(target_range)
    else:
        # Hostname
        live_hosts = [target_range]

    if not live_hosts:
        return {"error": "No live hosts detected.", "results": [], "target": target_range}

    if callback:
        callback(f"Found {len(live_hosts)} live host(s). Starting port scan…")

    results = []
    active_ips: set = set()

    def tracked_scan(ip: str) -> dict:
        if callback:
            active_ips.add(ip)
            callback(f"Scanning: {', '.join(sorted(active_ips))}")
        try:
            return scan_target(ip, mode=mode, aggressive=aggressive, timeout=timeout)
        finally:
            active_ips.discard(ip)
            if callback:
                if active_ips:
                    callback(f"Scanning: {', '.join(sorted(active_ips))}")
                else:
                    callback("Processing results…")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(tracked_scan, ip): ip for ip in live_hosts}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                log_message(f"Future error: {e}", "error")

    return {
        "results": results,
        "target": target_range,
        "live_hosts_count": len(live_hosts),
    }
