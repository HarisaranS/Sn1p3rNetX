"""
drift_detector.py — Network Scan Drift Detection & Reporting
=============================================================
Detects and reports changes between successive network scans stored in the
Sn1p3rNetX SQLite history database.

Public API
----------
    get_latest_two_scans(target)  -> (prev_host_dict | None, curr_host_dict | None)
    compare_scans(old, new)       -> drift_dict
    diff_target(target)           -> drift_dict
    format_drift_report(diff)     -> str

Drift dict schema
-----------------
{
    "target":             str,
    "previous_ts":        str | None,   # ISO-8601 timestamp of older scan
    "current_ts":         str | None,   # ISO-8601 timestamp of newer scan
    "new_ports":          list[str],    # e.g. ["443/tcp", "8080/tcp"]
    "closed_ports":       list[str],
    "new_services":       list[str],    # service name/description strings
    "removed_services":   list[str],
    "new_cves":           list[str],    # CVE IDs
    "resolved_cves":      list[str],
    "risk_delta":         int,          # new_score - old_score
    "risk_direction":     str,          # 'IMPROVED' | 'DEGRADED' | 'UNCHANGED'
    "old_risk_score":     int,
    "new_risk_score":     int,
    "old_device_type":    str | None,
    "new_device_type":    str | None,
    "device_type_changed": bool,
    "severity":           str,          # 'CRITICAL_CHANGE' | 'SIGNIFICANT' | 'MINOR' | 'NO_CHANGE'
    "change_summary":     str,
    "error":              str | None,   # set only when something went wrong
}
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from config import DB_FILE

# ── Module-level logger ───────────────────────────────────────────────────────
_log = logging.getLogger("sn1p3rnetx.drift")


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _empty_drift(
    *,
    target: str = "",
    error: str | None = None,
    previous_ts: str | None = None,
    current_ts: str | None = None,
) -> dict:
    """Return a zeroed-out drift dictionary."""
    return {
        "target":              target,
        "previous_ts":         previous_ts,
        "current_ts":          current_ts,
        "new_ports":           [],
        "closed_ports":        [],
        "new_services":        [],
        "removed_services":    [],
        "new_cves":            [],
        "resolved_cves":       [],
        "risk_delta":          0,
        "risk_direction":      "UNCHANGED",
        "old_risk_score":      0,
        "new_risk_score":      0,
        "old_device_type":     None,
        "new_device_type":     None,
        "device_type_changed": False,
        "severity":            "NO_CHANGE",
        "change_summary":      "No changes detected.",
        "error":               error,
    }


def _extract_ports(host: dict) -> set[str]:
    """Return the set of open port strings (e.g. '443/tcp') for a host dict."""
    return set(host.get("open_ports", []))


def _extract_service_labels(host: dict) -> set[str]:
    """
    Return a normalised set of service label strings for comparison.
    Each label is '<port>/<proto>:<name>:<description[:60]>' so that minor
    banner differences do not create false positives.
    """
    labels: set[str] = set()
    for svc in host.get("services", []):
        port  = svc.get("port", "?")
        proto = svc.get("protocol", "tcp")
        name  = (svc.get("name") or "").strip().lower()
        desc  = (svc.get("description") or "").strip()[:60].lower()
        labels.add(f"{port}/{proto}:{name}:{desc}")
    return labels


def _extract_service_display(host: dict) -> dict[str, str]:
    """
    Return a mapping of canonical label -> human-readable service string
    for use in the formatted report.
    """
    mapping: dict[str, str] = {}
    for svc in host.get("services", []):
        port  = svc.get("port", "?")
        proto = svc.get("protocol", "tcp")
        name  = (svc.get("name") or "").strip().lower()
        desc  = (svc.get("description") or "").strip()[:60].lower()
        label = f"{port}/{proto}:{name}:{desc}"
        human = f"{port}/{proto} {name}" + (f" — {desc}" if desc else "")
        mapping[label] = human
    return mapping


def _extract_cves(host: dict) -> set[str]:
    """Return the set of all CVE IDs found across all services of a host."""
    cves: set[str] = set()
    for svc in host.get("services", []):
        for vuln in svc.get("vulnerabilities", []):
            cve_id = vuln.get("cve_id") or vuln.get("id") or ""
            if cve_id.upper().startswith("CVE-"):
                cves.add(cve_id.upper())
    return cves


def _classify_severity(
    new_ports: list,
    closed_ports: list,
    new_cves: list,
    risk_delta: int,
) -> str:
    """
    Classify the overall severity of detected drift.

    Rules (highest wins):
        CRITICAL_CHANGE  — any new CVEs OR risk_delta >= 20 OR >= 3 new ports
        SIGNIFICANT      — risk_delta >= 10 OR >= 2 new/closed ports
        MINOR            — any ports/services changed
        NO_CHANGE        — nothing changed
    """
    if new_cves or risk_delta >= 20 or len(new_ports) >= 3:
        return "CRITICAL_CHANGE"
    if risk_delta >= 10 or (len(new_ports) + len(closed_ports)) >= 2:
        return "SIGNIFICANT"
    if new_ports or closed_ports:
        return "MINOR"
    return "NO_CHANGE"


def _build_summary(diff: dict) -> str:
    """Build a concise human-readable change summary string."""
    parts: list[str] = []

    if diff["new_ports"]:
        parts.append(
            f"{len(diff['new_ports'])} new port(s) opened: {', '.join(diff['new_ports'][:5])}"
        )
    if diff["closed_ports"]:
        parts.append(
            f"{len(diff['closed_ports'])} port(s) closed: {', '.join(diff['closed_ports'][:5])}"
        )
    if diff["new_services"]:
        parts.append(f"{len(diff['new_services'])} new service(s) detected")
    if diff["removed_services"]:
        parts.append(f"{len(diff['removed_services'])} service(s) removed")
    if diff["new_cves"]:
        parts.append(
            f"{len(diff['new_cves'])} new CVE(s): {', '.join(list(diff['new_cves'])[:3])}"
        )
    if diff["resolved_cves"]:
        parts.append(f"{len(diff['resolved_cves'])} CVE(s) resolved")
    if diff["device_type_changed"]:
        parts.append(
            f"Device reclassified: {diff['old_device_type']} -> {diff['new_device_type']}"
        )

    delta = diff["risk_delta"]
    if delta != 0:
        direction = "up" if delta > 0 else "down"
        parts.append(
            f"Risk score moved {direction} by {abs(delta)} (now {diff['new_risk_score']})"
        )

    if not parts:
        return "No changes detected between the two most recent scans."

    return "; ".join(parts) + "."


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_latest_two_scans(target: str) -> tuple[dict | None, dict | None]:
    """
    Retrieve the two most recent scan host-dicts for *target* from the database.

    The function joins the ``scans`` and ``scan_hosts`` tables on scan_id and
    filters by ``scans.target``.  For each of the two most recent scan rows it
    deserialises the ``host_json`` column (falling back to the scan-level
    ``raw_json`` if ``host_json`` is absent).  When a scan produced multiple
    hosts the *first* host row is used — callers that need per-host diff should
    call :func:`compare_scans` directly with specific host dicts.

    Parameters
    ----------
    target:
        The target identifier (IP, CIDR, hostname) as stored in ``scans.target``.

    Returns
    -------
    (previous, current):
        A 2-tuple where *previous* is the older scan dict and *current* is the
        newer one.  Either element may be ``None`` if fewer than two scans exist
        for the given target, or if the stored JSON cannot be deserialised.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Fetch the two most recent distinct scan sessions for this target
        cur.execute(
            """
            SELECT s.id   AS scan_id,
                   s.timestamp,
                   s.raw_json,
                   h.host_json,
                   h.ip,
                   h.risk_score,
                   h.risk_level,
                   h.device_type
            FROM   scans s
            LEFT JOIN scan_hosts h ON h.scan_id = s.id
            WHERE  s.target = ?
            ORDER  BY s.id DESC, h.id ASC
            """,
            (target,),
        )
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error as exc:
        _log.error(
            "drift_detector: DB error reading scans for %s — %s", target, exc
        )
        return None, None

    if not rows:
        return None, None

    # Group by scan_id, preserving newest-first order; keep first host per scan
    seen_scan_ids: list[int] = []
    scan_rows: dict[int, sqlite3.Row] = {}
    for row in rows:
        sid = row["scan_id"]
        if sid not in scan_rows:
            seen_scan_ids.append(sid)
            scan_rows[sid] = row  # first host row per scan

    def _deserialise(row: sqlite3.Row) -> dict | None:
        """Try host_json first, then raw_json (list -> first element)."""
        host_json_str = row["host_json"]
        if host_json_str:
            try:
                data = json.loads(host_json_str)
                if isinstance(data, dict):
                    data.setdefault("_scan_timestamp", row["timestamp"])
                    return data
            except (json.JSONDecodeError, TypeError):
                pass

        raw_json_str = row["raw_json"]
        if raw_json_str:
            try:
                data = json.loads(raw_json_str)
                if isinstance(data, list) and data:
                    host = data[0]
                    host.setdefault("_scan_timestamp", row["timestamp"])
                    return host
                if isinstance(data, dict):
                    data.setdefault("_scan_timestamp", row["timestamp"])
                    return data
            except (json.JSONDecodeError, TypeError):
                pass

        # Fallback: synthesise a minimal dict from column values
        _log.warning(
            "drift_detector: no valid JSON for scan_id=%s target=%s; using column fallback",
            row["scan_id"],
            target,
        )
        return {
            "ip":              row["ip"],
            "risk_score":      row["risk_score"] or 0,
            "risk_level":      row["risk_level"] or "UNKNOWN",
            "device_type":     row["device_type"] or "Unknown",
            "open_ports":      [],
            "services":        [],
            "_scan_timestamp": row["timestamp"],
        }

    if len(seen_scan_ids) == 1:
        # Only one scan session recorded — no previous to compare against
        current = _deserialise(scan_rows[seen_scan_ids[0]])
        return None, current

    current  = _deserialise(scan_rows[seen_scan_ids[0]])
    previous = _deserialise(scan_rows[seen_scan_ids[1]])
    return previous, current


def compare_scans(old: dict, new: dict) -> dict:
    """
    Compare two host scan result dicts and return a structured drift dictionary.

    Parameters
    ----------
    old:
        Host dict from the older (previous) scan.
    new:
        Host dict from the newer (current) scan.

    Returns
    -------
    dict
        Drift dictionary with the schema documented at the top of this module.

    Notes
    -----
    * Port comparison is based on the ``open_ports`` list (e.g. ``"443/tcp"``).
    * Service comparison uses a normalised label so minor banner changes are not
      flagged as changes (see :func:`_extract_service_labels`).
    * CVE comparison matches on CVE-ID strings only.
    * ``risk_score`` is read from the top-level key; 0 is assumed if absent.
    * Identical dicts (same object or equal content) are detected early and
      return a NO_CHANGE result without further processing.
    """
    target = new.get("ip") or old.get("ip") or "unknown"
    old_ts = old.get("_scan_timestamp")
    new_ts = new.get("_scan_timestamp")

    # ── Guard: same object / equal content ────────────────────────────────────
    if old is new or old == new:
        result = _empty_drift(target=target, previous_ts=old_ts, current_ts=new_ts)
        result["change_summary"] = "Scans are identical — no changes detected."
        return result

    # ── Ports ─────────────────────────────────────────────────────────────────
    old_ports     = _extract_ports(old)
    new_ports_set = _extract_ports(new)

    new_ports    = sorted(new_ports_set - old_ports)
    closed_ports = sorted(old_ports - new_ports_set)

    # ── Services ──────────────────────────────────────────────────────────────
    old_svc_labels = _extract_service_labels(old)
    new_svc_labels = _extract_service_labels(new)
    new_svc_display = _extract_service_display(new)
    old_svc_display = _extract_service_display(old)

    added_svc_labels   = new_svc_labels - old_svc_labels
    removed_svc_labels = old_svc_labels - new_svc_labels

    new_services     = sorted(new_svc_display.get(lbl, lbl) for lbl in added_svc_labels)
    removed_services = sorted(old_svc_display.get(lbl, lbl) for lbl in removed_svc_labels)

    # ── CVEs ──────────────────────────────────────────────────────────────────
    old_cves     = _extract_cves(old)
    new_cves_set = _extract_cves(new)

    new_cves      = sorted(new_cves_set - old_cves)
    resolved_cves = sorted(old_cves - new_cves_set)

    # ── Risk score ────────────────────────────────────────────────────────────
    old_score  = int(old.get("risk_score", 0) or 0)
    new_score  = int(new.get("risk_score", 0) or 0)
    risk_delta = new_score - old_score

    if risk_delta > 0:
        risk_direction = "DEGRADED"
    elif risk_delta < 0:
        risk_direction = "IMPROVED"
    else:
        risk_direction = "UNCHANGED"

    # ── Device type ───────────────────────────────────────────────────────────
    old_device = (old.get("device_type") or "Unknown").strip()
    new_device = (new.get("device_type") or "Unknown").strip()
    device_type_changed = old_device.lower() != new_device.lower()

    # ── Severity ──────────────────────────────────────────────────────────────
    severity = _classify_severity(new_ports, closed_ports, new_cves, risk_delta)

    # ── Assemble ──────────────────────────────────────────────────────────────
    diff: dict[str, Any] = {
        "target":              target,
        "previous_ts":         old_ts,
        "current_ts":          new_ts,
        "new_ports":           new_ports,
        "closed_ports":        closed_ports,
        "new_services":        new_services,
        "removed_services":    removed_services,
        "new_cves":            new_cves,
        "resolved_cves":       resolved_cves,
        "risk_delta":          risk_delta,
        "risk_direction":      risk_direction,
        "old_risk_score":      old_score,
        "new_risk_score":      new_score,
        "old_device_type":     old_device,
        "new_device_type":     new_device,
        "device_type_changed": device_type_changed,
        "severity":            severity,
        "change_summary":      "",   # populated below
        "error":               None,
    }
    diff["change_summary"] = _build_summary(diff)
    return diff


def diff_target(target: str) -> dict:
    """
    Convenience wrapper: fetch the two latest scans for *target* from the DB
    and return a drift comparison dict.

    Parameters
    ----------
    target:
        The target identifier (IP, CIDR, hostname) as stored in ``scans.target``.

    Returns
    -------
    dict
        Drift dictionary.  The ``error`` key is set to a descriptive message
        when fewer than two scans are available or when a DB error occurs.
    """
    previous, current = get_latest_two_scans(target)

    if current is None:
        msg = f"No scan history found for target '{target}'."
        _log.warning("drift_detector: %s", msg)
        return _empty_drift(target=target, error=msg)

    if previous is None:
        msg = (
            f"Only one scan recorded for '{target}' — no previous scan to compare "
            "against.  Run another scan to enable drift detection."
        )
        _log.info("drift_detector: %s", msg)
        result = _empty_drift(
            target=target,
            current_ts=current.get("_scan_timestamp"),
            error=msg,
        )
        result["new_risk_score"]  = int(current.get("risk_score", 0) or 0)
        result["new_device_type"] = (current.get("device_type") or "Unknown").strip()
        result["change_summary"]  = msg
        return result

    diff = compare_scans(previous, current)
    diff["target"] = target  # ensure target is always the query string
    return diff


def format_drift_report(diff: dict) -> str:
    """
    Render a human-readable drift report with emoji indicators.

    Symbols
    -------
    :emoji:`check_mark_button`  Improvement / resolved item
    :emoji:`cross_mark`  Degradation / new threat
    :emoji:`new_button`  New item (newly opened ports, services)
    :emoji:`locked`  Closed port
    :emoji:`information`  Informational
    :emoji:`warning`  Warning
    :emoji:`rotating_light`  Critical change

    Parameters
    ----------
    diff:
        Drift dictionary as returned by :func:`compare_scans` or
        :func:`diff_target`.

    Returns
    -------
    str
        Multi-line formatted report suitable for terminal output.
    """
    lines: list[str] = []
    sep  = "-" * 60
    sep2 = "=" * 60

    target     = diff.get("target", "unknown")
    prev_ts    = diff.get("previous_ts") or "N/A"
    curr_ts    = diff.get("current_ts")  or "N/A"
    severity   = diff.get("severity", "NO_CHANGE")
    direction  = diff.get("risk_direction", "UNCHANGED")
    old_score  = diff.get("old_risk_score", 0)
    new_score  = diff.get("new_risk_score",  0)
    risk_delta = diff.get("risk_delta", 0)

    severity_icon = {
        "CRITICAL_CHANGE": "",
        "SIGNIFICANT":     " ",
        "MINOR":           " ",
        "NO_CHANGE":       "",
    }.get(severity, " ")

    direction_icon = {
        "DEGRADED":  "",
        "IMPROVED":  "",
        "UNCHANGED": "",
    }.get(direction, "")

    lines.append(sep2)
    lines.append(f"    NETWORK DRIFT REPORT  —  {target}")
    lines.append(sep2)
    lines.append(f"  Previous scan : {prev_ts}")
    lines.append(f"  Current scan  : {curr_ts}")
    lines.append(sep)

    # ── Error / first-run notice ──────────────────────────────────────────────
    error = diff.get("error")
    if error:
        lines.append(f"     Notice : {error}")
        lines.append(sep2)
        return "\n".join(lines)

    # ── Overall severity & risk ───────────────────────────────────────────────
    lines.append(f"  {severity_icon}  Severity    : {severity}")
    lines.append(
        f"  {direction_icon}  Risk Score  : {old_score} -> {new_score}  "
        f"(delta {risk_delta:+d},  {direction})"
    )
    lines.append(sep)

    # ── Device type ───────────────────────────────────────────────────────────
    old_dev = diff.get("old_device_type") or "Unknown"
    new_dev = diff.get("new_device_type") or "Unknown"
    if diff.get("device_type_changed"):
        lines.append("    Device reclassified:")
        lines.append(f"        Was : {old_dev}")
        lines.append(f"        Now : {new_dev}")
    else:
        lines.append(f"     Device type : {new_dev}  (unchanged)")
    lines.append(sep)

    # ── Ports ─────────────────────────────────────────────────────────────────
    new_ports    = diff.get("new_ports", [])
    closed_ports = diff.get("closed_ports", [])

    if new_ports:
        lines.append(f"    New open ports ({len(new_ports)}):")
        for p in new_ports:
            lines.append(f"          {p}")
    else:
        lines.append("    No new ports opened")

    if closed_ports:
        lines.append(f"    Ports closed ({len(closed_ports)}):")
        for p in closed_ports:
            lines.append(f"          {p}")
    else:
        lines.append("     No ports closed")
    lines.append(sep)

    # ── Services ──────────────────────────────────────────────────────────────
    new_svcs     = diff.get("new_services", [])
    removed_svcs = diff.get("removed_services", [])

    if new_svcs:
        lines.append(f"    New services ({len(new_svcs)}):")
        for s in new_svcs:
            lines.append(f"          {s}")
    else:
        lines.append("    No new services detected")

    if removed_svcs:
        lines.append(f"    Removed services ({len(removed_svcs)}):")
        for s in removed_svcs:
            lines.append(f"          {s}")
    lines.append(sep)

    # ── CVEs ──────────────────────────────────────────────────────────────────
    new_cves      = diff.get("new_cves", [])
    resolved_cves = diff.get("resolved_cves", [])

    if new_cves:
        lines.append(f"    NEW CVEs detected ({len(new_cves)}):")
        for c in new_cves:
            lines.append(f"          {c}")
    else:
        lines.append("    No new CVEs detected")

    if resolved_cves:
        lines.append(f"    Resolved CVEs ({len(resolved_cves)}):")
        for c in resolved_cves:
            lines.append(f"          {c}")
    lines.append(sep)

    # ── Summary ───────────────────────────────────────────────────────────────
    lines.append(f"    Summary: {diff.get('change_summary', 'N/A')}")
    lines.append(sep2)

    return "\n".join(lines)
