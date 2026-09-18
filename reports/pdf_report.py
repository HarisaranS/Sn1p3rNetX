"""
pdf_report.py — Professional PDF report generator using fpdf2.

Features:
  • Cover page with overall risk gauge
  • Per-host summary with colored risk badge
  • Services table (full CVE + CVSS details)
  • MITRE ATT&CK section
  • AI Executive Summary rendered as plain text
  • Fixed: no blank trailing page
  • UTF-8 safe output
"""

try:
    from fpdf import FPDF
except ImportError:
    FPDF = object
from datetime import datetime
import os
from config import REPORT_DIR, VERSION, TOOL_NAME
from core.utils import log_message
from reports.json_report import _ensure_output_path


# ── Risk-level → RGB ──────────────────────────────────────────────────────────
_RISK_RGB = {
    "CRITICAL": (220, 38,  38),
    "HIGH":     (234, 88,  12),
    "MEDIUM":   (202, 138, 4),
    "LOW":      (22,  163, 74),
}


def _safe(text: str, limit: int = 0) -> str:
    """Strip non-latin chars and optionally truncate."""
    s = str(text).encode("latin-1", "replace").decode("latin-1")
    return s[:limit] if limit else s


class SnxPDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_host = ""

    def header(self):
        if self.page_no() == 1:
            return  # Cover page handles its own header
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, f"{TOOL_NAME} v{VERSION}  |  Security Report", align="L")
        self.cell(0, 8, f"Host: {self._current_host}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        gen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 10, f"Page {self.page_no()}  |  Generated: {gen}  |  For Authorised Use Only",
                  align="C")


def _cover_page(pdf: SnxPDF, scan_results: list):
    """Render a professional cover page."""
    pdf.add_page()
    pdf.set_fill_color(15, 15, 30)
    pdf.rect(0, 0, pdf.w, pdf.h, "F")

    # Title
    pdf.set_y(50)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(0, 200, 255)
    pdf.cell(0, 14, TOOL_NAME, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(180, 180, 200)
    pdf.cell(0, 10, "AI-Powered Network Risk Intelligence", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Version {VERSION}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)

    # Overall risk
    scores = [h.get("risk_score", 0) for h in scan_results]
    avg    = sum(scores) / len(scores) if scores else 0
    max_sc = max(scores) if scores else 0
    if max_sc >= 75:  level = "CRITICAL"
    elif max_sc >= 45: level = "HIGH"
    elif max_sc >= 20: level = "MEDIUM"
    else:             level = "LOW"

    r, g, b = _RISK_RGB.get(level, (22, 163, 74))
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "OVERALL RISK ASSESSMENT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(r, g, b)
    pdf.cell(0, 18, level, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 180, 200)
    pdf.cell(0, 8, f"Peak Score: {max_sc}/100   Average: {avg:.1f}/100", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)

    # Stats grid
    pdf.set_text_color(0, 200, 255)
    pdf.set_font("Helvetica", "B", 11)
    stats = [
        ("Hosts Scanned",  str(len(scan_results))),
        ("Report Date",    datetime.now().strftime("%Y-%m-%d")),
        ("Report Time",    datetime.now().strftime("%H:%M:%S")),
        ("Classification", "CONFIDENTIAL"),
    ]
    for label, val in stats:
        pdf.set_text_color(130, 130, 160)
        pdf.cell(80, 8, label + ":", align="R")
        pdf.set_text_color(220, 220, 255)
        pdf.cell(80, 8, val, align="L", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(-30)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 120)
    pdf.cell(0, 5, "This report is generated for authorised security assessment purposes only.", align="C")


def _host_page(pdf: SnxPDF, host: dict):
    """Render one host's section (may span multiple pages)."""
    ip         = host.get("ip", "?")
    score      = host.get("risk_score", 0)
    level      = host.get("risk_level", "LOW")
    metrics    = host.get("risk_metrics", {})
    services   = host.get("services", [])
    mitre      = host.get("mitre_techniques", [])
    device     = host.get("device_type", "Unknown")
    ai_summary = host.get("ai_analysis", "")

    pdf._current_host = ip
    pdf.add_page()

    r, g, b = _RISK_RGB.get(level, (22, 163, 74))

    # ── Host banner ──────────────────────────────────────────────────────────
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 12, f"  Host: {ip}   [{level}]  Score: {score}/100",
             fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ── Info grid ─────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)

    info_rows = [
        ("Device Type",    _safe(device)),
        ("MAC / Vendor",   _safe(f"{host.get('mac', 'N/A')} / {host.get('vendor', 'N/A')}")),
        ("OS",             _safe(host.get("os", "N/A"))),
        ("Status",         _safe(host.get("status", "N/A"))),
        ("Open Ports",     str(metrics.get("total_open_ports", 0))),
        ("Critical CVEs",  str(metrics.get("critical_cves", 0))),
        ("High CVEs",      str(metrics.get("high_cves", 0))),
        ("Max CVSS",       str(metrics.get("max_cvss", 0))),
        ("Attack Surface", f"{metrics.get('attack_surface_idx', 0)}%"),
    ]
    for label, val in info_rows:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(55, 7, label + ":", border="B")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(0,  7, val[:80], border="B", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(5)

    # ── Services table ────────────────────────────────────────────────────────
    if services:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(60, 60, 90)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, "  Open Services & Vulnerabilities", fill=True,
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

        # Header row
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(220, 220, 235)
        pdf.set_text_color(20, 20, 20)
        col_w = [22, 42, 80, 14, 32]
        headers = ["Port", "Service", "CVE / Description", "CVSS", "Severity"]
        for w, h in zip(col_w, headers):
            pdf.cell(w, 7, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for svc in services:
            vulns = svc.get("vulnerabilities", [])
            port_str = f"{svc.get('port')}/{svc.get('protocol', 'tcp')}"
            desc_str = _safe(svc.get("description", ""), 38)

            if vulns:
                for i, v in enumerate(vulns[:3]):
                    sev = v.get("severity", "LOW")
                    rv, gv, bv = _RISK_RGB.get(sev, (22, 163, 74))
                    cvss_s = str(v.get("cvss_score", "?"))
                    cve_desc = _safe(v.get("description", ""), 55)
                    cve_id   = _safe(v.get("cve_id", ""), 16)

                    pdf.set_fill_color(rv, gv, bv)
                    pdf.set_text_color(255, 255, 255)

                    pdf.cell(col_w[0], 6, port_str if i == 0 else "", border=1)
                    pdf.cell(col_w[1], 6, desc_str if i == 0 else "", border=1)
                    pdf.set_text_color(20, 20, 20)
                    pdf.cell(col_w[2], 6, f"{cve_id}: {cve_desc}"[:55], border=1)
                    pdf.set_fill_color(rv, gv, bv)
                    pdf.set_text_color(255, 255, 255)
                    pdf.cell(col_w[3], 6, cvss_s, border=1, align="C")
                    pdf.cell(col_w[4], 6, sev[:10], border=1, fill=True, align="C")
                    pdf.ln()
            else:
                pdf.set_text_color(20, 20, 20)
                pdf.cell(col_w[0], 6, port_str, border=1)
                pdf.cell(col_w[1], 6, desc_str, border=1)
                pdf.cell(col_w[2], 6, "No known CVEs matched", border=1)
                pdf.cell(col_w[3], 6, "—", border=1, align="C")
                pdf.cell(col_w[4], 6, "—", border=1, align="C")
                pdf.ln()

        pdf.ln(4)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    if mitre:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(80, 20, 20)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, "  MITRE ATT&CK Techniques", fill=True,
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(30, 30, 30)
        for t in mitre[:8]:
            pdf.cell(28, 6, _safe(t["technique_id"]), border=1, align="C")
            pdf.cell(0,  6, _safe(t["technique_name"], 70), border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ── AI Analysis ──────────────────────────────────────────────────────────
    if ai_summary and not ai_summary.startswith(""):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(0, 80, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, "  AI Security Assessment", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(20, 20, 20)
        # Strip markdown syntax for PDF rendering
        clean = ai_summary.replace("**", "").replace("##", "").replace("#", "").replace("*", "-")
        pdf.multi_cell(0, 5, _safe(clean))
        pdf.ln(3)


def generate_pdf_report(scan_results: list, output_file: str = None) -> str:
    """Main entry — writes PDF report, returns path."""
    output_file = _ensure_output_path(output_file, ".pdf")

    if FPDF is object:
        print("[-] PDF generation unavailable — `fpdf2` Python package is missing.")
        print("    Ensure you are running in your virtual environment (e.g., `sudo -E python3`).")
        return ""

    pdf = SnxPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)

    # Cover
    _cover_page(pdf, scan_results)

    # One section per host (no trailing blank page — loop without add_page at end)
    for host in scan_results:
        _host_page(pdf, host)

    try:
        pdf.output(output_file)
        log_message(f"PDF report written to {output_file}")
        print(f"[+] PDF report saved to: {output_file}")
        return output_file
    except Exception as e:
        log_message(f"PDF generation failed: {e}", "error")
        print(f"[-] PDF generation failed: {e}")
        return ""
