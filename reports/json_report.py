import json
import os
from datetime import datetime
from config import REPORT_DIR, VERSION, TOOL_NAME, SCHEMA_VER
from core.utils import log_message


def _ensure_output_path(output_file: str, suffix: str) -> str:
    """
    Ensure the output directory exists and is writable.
    Falls back to the current working directory if REPORT_DIR is not writable.
    """
    if not output_file:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sn1p3rnetx_report_{ts}{suffix}"
        output_file = os.path.join(REPORT_DIR, filename)

    directory = os.path.dirname(os.path.abspath(output_file))
    try:
        os.makedirs(directory, exist_ok=True)
        # Quick writability test
        test = os.path.join(directory, ".snx_write_test")
        open(test, "w").close()
        os.remove(test)
    except (PermissionError, OSError):
        # Fallback: write to the current working directory
        filename = os.path.basename(output_file)
        output_file = os.path.join(os.getcwd(), filename)

    return output_file


def generate_json_report(scan_results: list, output_file: str = None) -> str:
    """
    Write a structured JSON report with metadata.
    Saves to REPORT_DIR by default, falls back to cwd if not writable.
    """
    output_file = _ensure_output_path(output_file, ".json")

    # ── Build metadata wrapper ────────────────────────────────────────────────
    report = {
        "schema_version": SCHEMA_VER,
        "tool":           TOOL_NAME,
        "tool_version":   VERSION,
        "generated_at":   datetime.now().isoformat(),
        "host_count":     len(scan_results),
        "overall_risk":   _compute_overall_risk(scan_results),
        "hosts":          scan_results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    log_message(f"JSON report written to {output_file}")
    print(f"[+] JSON report saved to: {output_file}")
    return output_file


def _compute_overall_risk(hosts: list) -> dict:
    if not hosts:
        return {"score": 0, "level": "LOW"}
    avg   = sum(h.get("risk_score", 0) for h in hosts) / len(hosts)
    score = round(avg, 1)
    if score >= 75:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level}
