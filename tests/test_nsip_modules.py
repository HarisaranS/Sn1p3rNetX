import pytest
from core.business_risk import estimate_breach_cost
from core.compliance import run_compliance_check
from core.remediation import get_remediations
from core.threat_actors import profile_threat_actors

def test_business_risk():
    host = {"risk_score": 100}
    res = estimate_breach_cost(host)
    assert res["business_risk_level"] == "CATASTROPHIC"
    assert res["breach_probability_pct"] == 80
    
def test_compliance():
    host = {"open_ports": ["3389/tcp"], "risk_score": 100}
    res = run_compliance_check(host, "PCI-DSS")
    assert res["score_pct"] < 100
    assert any(f["id"] == "1.3" for f in res["failed"])

def test_remediation():
    host = {"services": [{"port": 3389}]}
    res = get_remediations(host)
    assert len(res) > 0
    assert "3389/tcp" in res[0]["commands_linux"]

def test_threat_actors():
    host = {"open_ports": ["3389/tcp", "445/tcp"]}
    actors = profile_threat_actors(host)
    assert len(actors) > 0
    assert actors[0]["match_score"] > 0
