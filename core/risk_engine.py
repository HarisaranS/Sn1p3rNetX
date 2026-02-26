def calculate_risk_score(host_data):
    """
    Calculates detailed risk score based on open ports and CVE severities.
    Returns the integer score and string level.
    """
    score = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    # Base points for surface area (open ports)
    open_ports = len(host_data.get('open_ports', []))
    score += (open_ports * 1)
    
    # Calculate points for vulnerabilities
    for service in host_data.get('services', []):
        vulns = service.get('vulnerabilities', [])
        if vulns:
            # Add base point for outdated/vulnerable service
            score += 3 
            
        for v in vulns:
            sev = v.get('severity', 'LOW').upper()
            if sev == 'CRITICAL':
                score += 10
                severity_counts["CRITICAL"] += 1
            elif sev == 'HIGH':
                score += 7
                severity_counts["HIGH"] += 1
            elif sev == 'MEDIUM':
                score += 4
                severity_counts["MEDIUM"] += 1
            else:
                score += 2
                severity_counts["LOW"] += 1

    # Cap score at 100
    score = min(score, 100)
    
    # Determine Level
    if score >= 50:
        risk_level = "CRITICAL"
    elif score >= 26:
        risk_level = "HIGH"
    elif score >= 11:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    return {
        "score": score,
        "risk_level": risk_level,
        "metrics": {
            "critical_cves": severity_counts["CRITICAL"],
            "high_cves": severity_counts["HIGH"],
            "medium_cves": severity_counts["MEDIUM"],
            "low_cves": severity_counts["LOW"],
            "total_open_ports": open_ports
        }
    }

def process_risk_for_hosts(scan_results):
    for host in scan_results:
        risk_data = calculate_risk_score(host)
        host['risk_score'] = risk_data['score']
        host['risk_level'] = risk_data['risk_level']
        host['risk_metrics'] = risk_data['metrics']
    return scan_results
