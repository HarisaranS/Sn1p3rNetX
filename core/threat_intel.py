"""
threat_intel.py — Live threat intelligence enrichment.

Integrates:
  • EPSS (Exploit Prediction Scoring System) — probability of exploitation
    in the next 30 days, sourced from api.first.org
  • CISA KEV (Known Exploited Vulnerabilities) — CISA's authoritative list
    of CVEs actively exploited in the wild
  
Enriched CVE dicts get:
  • epss_score:     float 0.0–1.0 (30-day exploit probability)
  • epss_percentile float 0.0–1.0 (relative to all CVEs)
  • in_cisa_kev:    bool
  • kev_due_date:   str|None (federal remediation deadline)
  • composite_risk_score: float (CVSS × EPSS × KEV_boost)
"""

from __future__ import annotations
import json
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Optional

# ── Cache file ─────────────────────────────────────────────────────────────────
_CACHE_DIR  = os.path.join(os.path.dirname(__file__), "..", ".cache")
_EPSS_CACHE = os.path.join(_CACHE_DIR, "epss_cache.json")
_KEV_CACHE  = os.path.join(_CACHE_DIR, "kev_catalog.json")
_CACHE_TTL  = 3600 * 6  # 6 hours

# ── Thread safety ──────────────────────────────────────────────────────────────
_lock    = threading.Lock()
_epss_db: dict[str, dict] = {}
_kev_db:  set[str]        = set()
_kev_due_dates: dict[str, str] = {}
_loaded  = False


def _ensure_cache_dir():
    os.makedirs(_CACHE_DIR, exist_ok=True)


def _load_epss_from_api(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a batch of CVE IDs from api.first.org."""
    try:
        import urllib.request
        chunk_size = 30
        results = {}
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            csv_ids = ",".join(chunk)
            url = f"https://api.first.org/data/1.0/epss?cve={csv_ids}&pretty=false"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            for item in data.get("data", []):
                results[item["cve"]] = {
                    "score":      float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
        return results
    except Exception:
        return {}


def _load_kev_from_api() -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    try:
        import urllib.request
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with urllib.request.urlopen(url, timeout=10) as resp:
            catalog = json.loads(resp.read().decode())
        return catalog
    except Exception:
        return {}


def _save_json(path: str, data):
    _ensure_cache_dir()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "data": data}, f, ensure_ascii=False)
    except Exception:
        pass


def _load_json(path: str, ttl: float = _CACHE_TTL) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if time.time() - obj.get("ts", 0) < ttl:
            return obj.get("data")
    except Exception:
        pass
    return None


def _initialize(cve_ids: list[str]):
    """Load EPSS and KEV data into module-level caches."""
    global _epss_db, _kev_db, _kev_due_dates, _loaded

    with _lock:
        if _loaded:
            return

        # ── EPSS ──────────────────────────────────────────────────────────────
        cached_epss = _load_json(_EPSS_CACHE)
        if cached_epss:
            _epss_db = cached_epss
        else:
            fetched = _load_epss_from_api(cve_ids)
            if fetched:
                _epss_db = fetched
                _save_json(_EPSS_CACHE, fetched)

        # ── CISA KEV ──────────────────────────────────────────────────────────
        cached_kev = _load_json(_KEV_CACHE, ttl=3600 * 24)  # 24h TTL for KEV
        if cached_kev:
            for v in cached_kev.get("vulnerabilities", []):
                cve = v.get("cveID", "")
                _kev_db.add(cve)
                _kev_due_dates[cve] = v.get("dueDate", "")
        else:
            catalog = _load_kev_from_api()
            if catalog:
                _save_json(_KEV_CACHE, catalog)
                for v in catalog.get("vulnerabilities", []):
                    cve = v.get("cveID", "")
                    _kev_db.add(cve)
                    _kev_due_dates[cve] = v.get("dueDate", "")

        _loaded = True


def get_epss(cve_id: str) -> dict:
    """Return EPSS data for a CVE ID."""
    return _epss_db.get(cve_id, {"score": 0.0, "percentile": 0.0})


def in_kev(cve_id: str) -> bool:
    """Return True if the CVE is in the CISA KEV catalog."""
    return cve_id in _kev_db


def kev_due_date(cve_id: str) -> Optional[str]:
    """Return the CISA remediation due date for a KEV entry, if available."""
    return _kev_due_dates.get(cve_id)


def composite_risk_score(
    cvss:          float,
    epss_score:    float,
    is_kev:        bool,
    asset_weight:  float = 1.0,
) -> float:
    """
    Compute a composite risk score (0–10) combining:
      • CVSS (base severity)
      • EPSS (real-world exploit probability)
      • KEV (confirmed active exploitation — 2× multiplier)
      • Asset criticality weight

    Formula (simplified FAIR-inspired):
        base = cvss × (1 + epss × 0.5)
        kev_factor = 1.8 if kev else 1.0
        score = min(base × kev_factor × asset_weight, 10.0)
    """
    base   = cvss * (1 + epss_score * 0.5)
    kev_f  = 1.8 if is_kev else 1.0
    return round(min(base * kev_f * asset_weight, 10.0), 2)


def enrich_cves_with_threat_intel(hosts: list[dict]) -> list[dict]:
    """
    Enrich all CVE entries in every host's services with EPSS + KEV data.
    Adds fields: epss_score, in_cisa_kev, kev_due_date, composite_risk.
    """
    # Collect all CVE IDs
    all_cve_ids = []
    for host in hosts:
        for svc in host.get("services", []):
            for v in svc.get("vulnerabilities", []):
                cid = v.get("cve_id", "")
                if cid and cid.startswith("CVE-"):
                    all_cve_ids.append(cid)

    if not all_cve_ids:
        return hosts

    # Initialize (fetches from APIs if cache is stale)
    try:
        _initialize(all_cve_ids)
    except Exception:
        return hosts  # Fail gracefully — don't crash if offline

    # Enrich
    for host in hosts:
        host_kev_count  = 0
        host_epss_max   = 0.0
        for svc in host.get("services", []):
            for v in svc.get("vulnerabilities", []):
                cid   = v.get("cve_id", "")
                epss  = get_epss(cid)
                is_in = in_kev(cid)
                due   = kev_due_date(cid) if is_in else None

                v["epss_score"]    = epss["score"]
                v["epss_pct"]      = epss["percentile"]
                v["in_cisa_kev"]   = is_in
                v["kev_due_date"]  = due
                v["composite_risk"] = composite_risk_score(
                    cvss       = float(v.get("cvss_score", 0)),
                    epss_score = epss["score"],
                    is_kev     = is_in,
                )

                if is_in:
                    host_kev_count += 1
                    # Escalate severity if KEV
                    if v.get("severity") not in ("CRITICAL",):
                        v["severity"] = "CRITICAL"

                host_epss_max = max(host_epss_max, epss["score"])

            # Update service max_composite_risk
            if svc.get("vulnerabilities"):
                svc["max_composite_risk"] = max(
                    v.get("composite_risk", 0) for v in svc["vulnerabilities"]
                )

        # Surface to host metrics
        metrics = host.setdefault("risk_metrics", {})
        metrics["kev_count"]   = host_kev_count
        metrics["max_epss"]    = round(host_epss_max, 4)
        if host_kev_count > 0:
            # KEV presence bumps risk score
            current = host.get("risk_score", 0)
            host["risk_score"] = min(100, current + host_kev_count * 8)
            host["has_kev_cves"] = True
        else:
            host["has_kev_cves"] = False

    return hosts


def get_intel_summary(hosts: list[dict]) -> dict:
    """Return network-level threat intel summary."""
    total_kev = sum(h.get("risk_metrics", {}).get("kev_count", 0) for h in hosts)
    max_epss  = max((h.get("risk_metrics", {}).get("max_epss", 0) for h in hosts), default=0)
    kev_hosts = [h.get("ip") for h in hosts if h.get("has_kev_cves")]
    return {
        "total_kev_cves": total_kev,
        "max_epss":       max_epss,
        "kev_hosts":      kev_hosts,
        "intel_available": _loaded,
    }
