"""
remediation.py — Generates exact shell commands to remediate findings.
"""

def get_remediations(host_data: dict) -> list[dict]:
    rems = []
    for svc in host_data.get("services", []):
        port = svc.get("port")
        if port in (3389, 3390):
            rems.append({
                "priority": 1,
                "category": "Access Control",
                "description": f"Close RDP port {port} to internet",
                "commands_linux": f"sudo ufw deny {port}/tcp && sudo systemctl stop xrdp",
                "commands_windows": f"netsh advfirewall firewall add rule name=\"Block RDP {port}\" dir=in action=block protocol=TCP localport={port}"
            })
        elif port == 3306:
            rems.append({
                "priority": 2,
                "category": "Database Security",
                "description": "Secure MySQL from external access",
                "commands_linux": "mysql -e \"DELETE FROM mysql.user WHERE Host='%';\" && sudo systemctl restart mysql",
                "commands_windows": ""
            })
    return rems

def generate_remediation_script(host_data: dict, platform: str = 'linux') -> str:
    rems = get_remediations(host_data)
    script = "#!/bin/bash\n# Sn1p3rNetX Auto-Remediation Script\n\n"
    for r in sorted(rems, key=lambda x: x["priority"]):
        script += f"# [Priority {r['priority']}] {r['description']}\n"
        script += f"{r['commands_linux']}\n\n"
    return script
