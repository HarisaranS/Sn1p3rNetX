import pytest
from core.cve_lookup import suggest_exploits

def test_cve_lookup_known_service():
    vulns = suggest_exploits("apache/2.4.49", port=80)
    # Should match CVE-2021-41773
    assert any(v["cve_id"] == "CVE-2021-41773" for v in vulns)
    assert any(v["severity"] == "CRITICAL" for v in vulns)

def test_cve_lookup_known_port():
    vulns = suggest_exploits("", port=3389)
    # Port 3389 should hint BlueKeep
    assert any(v["cve_id"] == "CVE-2019-0708" for v in vulns)

def test_cve_lookup_empty():
    assert suggest_exploits("", port=0) == []
