import pytest
from core.drift_detector import compare_scans

def test_compare_scans_identical():
    old = {"ip": "1.1.1.1", "risk_score": 50, "open_ports": ["80/tcp"]}
    new = {"ip": "1.1.1.1", "risk_score": 50, "open_ports": ["80/tcp"]}
    diff = compare_scans(old, new)
    assert diff["risk_delta"] == 0
    assert diff["severity"] == "NO_CHANGE"
    assert len(diff["new_ports"]) == 0

def test_compare_scans_degraded():
    old = {"ip": "1.1.1.1", "risk_score": 20, "open_ports": ["80/tcp"]}
    new = {"ip": "1.1.1.1", "risk_score": 90, "open_ports": ["80/tcp", "3389/tcp"]}
    diff = compare_scans(old, new)
    assert diff["risk_delta"] == 70
    assert diff["severity"] == "CRITICAL_CHANGE"
    assert "3389/tcp" in diff["new_ports"]
