import subprocess
import json

def suggest_exploits(service_str):
    """
    Offline CVE / Exploit matcher using a curated list of high-severity
    and common vulnerabilities for specific services.
    Falls back to trying searchsploit if available.
    """
    if not service_str:
        return []
        
    known = [
        # === Web servers ===
        ("apache", "CVE-2024-40725 (Apache Source Disclosure)", "HIGH"),
        ("apache/2.4.49", "CVE-2021-41773 (Path Traversal RCE)", "CRITICAL"),
        ("nginx", "CVE-2022-41741 (Memory leak via header manipulation)", "MEDIUM"),
        ("tomcat", "CVE-2020-1938 (Ghostcat AJP RCE)", "CRITICAL"),

        # === SSH & FTP ===
        ("openssh", "CVE-2024-6387 (OpenSSH RCE - Signal handler race)", "HIGH"),
        ("dropbear", "IoT SSH - weak auth vector", "MEDIUM"),
        ("vsftpd", "CVE-2011-2523 (Backdoor exploit)", "CRITICAL"),

        # === SMB & RDP ===
        ("smb", "MS17-010 (EternalBlue RCE)", "CRITICAL"),
        ("rdp", "CVE-2019-0708 (BlueKeep RCE)", "CRITICAL"),

        # === Databases ===
        ("mysql", "Weak root login / CVE-2022-31626", "HIGH"),
        ("mongodb", "CVE-2017-15535 (No auth exposure)", "HIGH"),
        ("redis", "Config write RCE / CVE-2022-0543", "CRITICAL"),

        # === DevOps ===
        ("docker", "CVE-2019-5736 (Container breakout)", "CRITICAL"),
        ("kubelet", "CVE-2018-1002105 (API bypass)", "CRITICAL"),
        ("jenkins", "CVE-2018-1000861 (Script console RCE)", "CRITICAL"),

        # === Other ===
        ("rabbitmq", "Default creds dashboard CVE-2021-32719", "HIGH"),
        ("weblogic", "CVE-2020-2551 (Admin RCE)", "CRITICAL"),
        ("vnc", "Open VNC - no auth RFB protocol", "HIGH"),
        ("fortinet", "CVE-2023-27997 (SSL VPN Pre-auth RCE)", "CRITICAL"),
    ]
    
    found_cves = []
    service_lower = service_str.lower()
    
    for k, v_desc, severity in known:
        if k in service_lower:
            found_cves.append({
                "cve_id": v_desc.split(" ")[0] if "CVE" in v_desc else "Vuln",
                "description": v_desc,
                "severity": severity
            })
            
    # Try SearchSploit integration
    try:
        ss = subprocess.getoutput(f"searchsploit --exclude='dos' {service_str}").splitlines()
        cves = [line.strip() for line in ss if "CVE" in line][:3]
        for cve_line in cves:
            parts = cve_line.split(" - ")
            cve_id = parts[-1].strip() if len(parts) > 1 else "Unknown_CVE"
            found_cves.append({
                "cve_id": cve_id,
                "description": cve_line,
                "severity": "HIGH" # Searchsploit defaults to high for RCEs
            })
    except Exception:
        pass
        
    # Deduplicate
    unique_cves = {c['description']: c for c in found_cves}.values()
    return list(unique_cves)

def enrich_services_with_cves(scan_results):
    """
    Takes the parsed scan array and adds 'vulnerabilities' keys to services.
    """
    for host in scan_results:
        if 'services' in host:
            for service in host['services']:
                cves = suggest_exploits(service.get('description', ''))
                service['vulnerabilities'] = cves
    return scan_results
