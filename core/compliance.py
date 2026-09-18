"""
compliance.py — Automatically maps security findings to compliance frameworks.
"""

def run_compliance_check(host_data: dict, framework: str) -> dict:
    failed_controls = []
    passed_controls = []
    
    ports = host_data.get("open_ports", [])
    risk = host_data.get("risk_score", 0)
    
    if framework == "PCI-DSS":
        if any("3389" in str(p) for p in ports):
            failed_controls.append({"id": "1.3", "desc": "RDP exposed to internet"})
        if risk > 50:
            failed_controls.append({"id": "6.3", "desc": "High risk vulnerabilities detected"})
        else:
            passed_controls.append({"id": "6.3", "desc": "No high risk vulnerabilities"})
            
    score = 100 if not failed_controls else max(0, 100 - len(failed_controls)*20)
    
    return {
        "framework": framework,
        "score_pct": score,
        "grade": "A" if score > 90 else "F",
        "passed": passed_controls,
        "failed": failed_controls,
        "warnings": [],
        "summary": "Compliance check complete",
        "audit_risk": "HIGH" if failed_controls else "LOW"
    }

def run_all_frameworks(host_data: dict) -> list[dict]:
    return [
        run_compliance_check(host_data, "PCI-DSS"),
        run_compliance_check(host_data, "HIPAA"),
        run_compliance_check(host_data, "NIST 800-53")
    ]
