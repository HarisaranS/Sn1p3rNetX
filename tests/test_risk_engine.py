import pytest
from core.risk_engine import process_risk_for_hosts

def test_process_risk_for_hosts_empty():
    assert process_risk_for_hosts([]) == []

def test_process_risk_for_hosts_critical():
    host = {
        "ip": "10.0.0.1",
        "open_ports": ["3389/tcp"],
        "services": [
            {
                "port": 3389,
                "vulnerabilities": [
                    {"cve_id": "CVE-2019-0708", "severity": "CRITICAL", "cvss_score": 9.8}
                ]
            }
        ]
    }
    res = process_risk_for_hosts([host])
    assert len(res) == 1
    assert res[0]["risk_level"] == "MEDIUM"
    assert res[0]["risk_score"] > 20

def test_process_risk_device_classification():
    host = {
        "ip": "10.0.0.2",
        "open_ports": ["3306/tcp"],
        "services": [
            {"port": 3306, "description": "MySQL 8.0"}
        ]
    }
    res = process_risk_for_hosts([host])
    assert "Database" in res[0]["device_type"]
