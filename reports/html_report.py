"""
html_report.py — Dark-themed interactive HTML report.

Features:
  • Dark cybersecurity dashboard aesthetic
  • Chart.js risk score doughnut + bar charts
  • Interactive collapsible host cards
  • CVE severity badges with color coding
  • MITRE ATT&CK technique tags
  • AI analysis sections
  • Print-friendly CSS
  • Fully self-contained (no external dependencies at runtime)
"""

import json
import os
from datetime import datetime
from config import REPORT_DIR, VERSION, TOOL_NAME
from core.utils import log_message
from reports.json_report import _ensure_output_path

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#16a34a",
}

_RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#16a34a",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{tool} v{version} — Security Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  :root {{
    --bg:        #0a0a0f;
    --bg2:       #0f0f1a;
    --bg3:       #161625;
    --card:      #1a1a2e;
    --card2:     #16213e;
    --border:    #2a2a4a;
    --accent:    #00d4ff;
    --accent2:   #7c3aed;
    --text:      #e2e8f0;
    --text2:     #94a3b8;
    --text3:     #64748b;
    --crit:      #dc2626;
    --high:      #ea580c;
    --med:       #ca8a04;
    --low:       #16a34a;
    --glow:      0 0 20px rgba(0,212,255,0.15);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
  }}
  /* ── Header ── */
  .site-header {{
    background: linear-gradient(135deg, #0a0a1a 0%, #0f0f2e 50%, #0a0a1a 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .site-header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(0,212,255,0.08) 0%, transparent 70%);
  }}
  .site-header h1 {{
    font-size: 2.5rem;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.05em;
  }}
  .site-header .subtitle {{
    color: var(--text2);
    margin-top: 0.4rem;
    font-size: 0.95rem;
    font-weight: 300;
  }}
  .site-header .meta-row {{
    display: flex;
    justify-content: center;
    gap: 2rem;
    margin-top: 1.2rem;
    flex-wrap: wrap;
  }}
  .meta-chip {{
    background: rgba(0,212,255,0.08);
    border: 1px solid rgba(0,212,255,0.2);
    border-radius: 999px;
    padding: 0.25rem 0.9rem;
    font-size: 0.8rem;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
  }}
  /* ── Layout ── */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  /* ── Summary cards ── */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .stat-card:hover {{
    transform: translateY(-3px);
    box-shadow: var(--glow);
  }}
  .stat-card .stat-val {{
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
  }}
  .stat-card .stat-label {{
    font-size: 0.78rem;
    color: var(--text3);
    margin-top: 0.2rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  /* ── Charts ── */
  .charts-row {{
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
  }}
  .chart-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
  }}
  .chart-card h3 {{
    font-size: 0.85rem;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 1rem;
  }}
  /* ── Host Cards ── */
  .hosts-section h2 {{
    font-size: 1.1rem;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 1.2rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .host-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    margin-bottom: 1.5rem;
    overflow: hidden;
    transition: box-shadow 0.2s;
  }}
  .host-card:hover {{ box-shadow: 0 4px 30px rgba(0,0,0,0.4); }}
  .host-banner {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.4rem;
    cursor: pointer;
    user-select: none;
    background: var(--card2);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 0.8rem;
  }}
  .host-banner:hover {{ background: var(--bg3); }}
  .host-ip {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text);
  }}
  .host-meta {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    align-items: center;
  }}
  .risk-badge {{
    padding: 0.3rem 0.9rem;
    border-radius: 999px;
    font-size: 0.8rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.06em;
    color: #fff;
  }}
  .chip {{
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.15rem 0.6rem;
    font-size: 0.75rem;
    color: var(--text2);
    font-family: 'JetBrains Mono', monospace;
  }}
  .score-bar-wrap {{
    width: 120px;
    height: 8px;
    background: var(--bg);
    border-radius: 999px;
    overflow: hidden;
  }}
  .score-bar {{
    height: 100%;
    border-radius: 999px;
    transition: width 1s ease;
  }}
  .host-body {{
    padding: 1.4rem;
  }}
  .toggle-icon {{ font-size: 1.2rem; transition: transform 0.2s; }}
  .host-card.collapsed .host-body {{ display: none; }}
  .host-card.collapsed .toggle-icon {{ transform: rotate(-90deg); }}
  /* ── Info grid ── */
  .info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.8rem;
    margin-bottom: 1.5rem;
  }}
  .info-item {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.7rem 1rem;
  }}
  .info-item label {{
    display: block;
    font-size: 0.7rem;
    color: var(--text3);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.2rem;
  }}
  .info-item span {{
    font-size: 0.88rem;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
  }}
  /* ── Tables ── */
  .section-title {{
    font-size: 0.78rem;
    color: var(--text3);
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin: 1.5rem 0 0.7rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }}
  th {{
    background: var(--bg3);
    color: var(--text2);
    font-weight: 600;
    padding: 0.6rem 0.8rem;
    text-align: left;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.55rem 0.8rem;
    border-bottom: 1px solid rgba(42,42,74,0.5);
    vertical-align: top;
  }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .mono {{ font-family: 'JetBrains Mono', monospace; }}
  .sev-badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    color: #fff;
  }}
  .mitre-tag {{
    display: inline-block;
    background: rgba(124,58,237,0.15);
    border: 1px solid rgba(124,58,237,0.4);
    color: #a78bfa;
    border-radius: 4px;
    padding: 0.2rem 0.6rem;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
    margin: 0.15rem;
  }}
  /* ── AI Section ── */
  .ai-section {{
    background: var(--bg2);
    border: 1px solid rgba(0,212,255,0.2);
    border-radius: 10px;
    padding: 1.2rem;
    margin-top: 1.5rem;
  }}
  .ai-section h4 {{
    color: var(--accent);
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.8rem;
  }}
  .ai-content {{
    color: var(--text2);
    font-size: 0.88rem;
    white-space: pre-wrap;
    line-height: 1.7;
  }}
  /* ── Footer ── */
  .site-footer {{
    text-align: center;
    padding: 2rem;
    color: var(--text3);
    font-size: 0.78rem;
    border-top: 1px solid var(--border);
    margin-top: 3rem;
  }}
  /* ── Print ── */
  @media print {{
    body {{ background: #fff; color: #000; }}
    .host-banner {{ background: #f5f5f5; }}
    .host-card.collapsed .host-body {{ display: block !important; }}
    .site-header::before {{ display: none; }}
  }}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
</head>
<body>

<!-- ── HEADER ── -->
<header class="site-header">
  <h1>{tool}</h1>
  <p class="subtitle">AI-Powered Network Risk Intelligence &mdash; v{version}</p>
  <div class="meta-row">
    <span class="meta-chip"> {generated_at}</span>
    <span class="meta-chip"> {host_count} hosts</span>
    <span class="meta-chip"> {total_critical} critical</span>
    <span class="meta-chip"> {total_ports} open ports</span>
  </div>
</header>

<div class="container">

<!-- ── SUMMARY STATS ── -->
<div class="summary-grid">
  {stat_cards}
</div>

<!-- ── CHARTS ── -->
<div class="charts-row">
  <div class="chart-card">
    <h3>Risk Distribution</h3>
    <canvas id="riskDoughnut" height="220"></canvas>
  </div>
  <div class="chart-card">
    <h3>Host Risk Scores</h3>
    <canvas id="hostBar" height="220"></canvas>
  </div>
</div>

<!-- ── HOST CARDS ── -->
<div class="hosts-section">
  <h2> Host Intelligence Reports</h2>
  {host_cards}
</div>

</div>

<!-- ── FOOTER ── -->
<footer class="site-footer">
  <p>Generated by <strong>{tool} v{version}</strong> &mdash; For authorised security assessment purposes only.</p>
  <p style="margin-top:0.3rem">Report Date: {generated_at}</p>
</footer>

<script>
// Chart data injected by Python
const chartData = {chart_data_json};

// Doughnut — risk distribution
new Chart(document.getElementById('riskDoughnut'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{{ data: chartData.dist, backgroundColor: ['#dc2626','#ea580c','#ca8a04','#16a34a'], borderWidth: 0 }}]
  }},
  options: {{
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
    cutout: '65%'
  }}
}});

// Bar — per-host scores
new Chart(document.getElementById('hostBar'), {{
  type: 'bar',
  data: {{
    labels: chartData.ips,
    datasets: [{{
      label: 'Risk Score',
      data: chartData.scores,
      backgroundColor: chartData.colors,
      borderRadius: 5,
      maxBarThickness: 30,
    }}]
  }},
  options: {{
    maintainAspectRatio: false,
    scales: {{
      y: {{ min: 0, max: 100, grid: {{ color: '#1e1e3a' }}, ticks: {{ color: '#94a3b8' }} }},
      x: {{ grid: {{ display: false }}, ticks: {{ color: '#94a3b8', font: {{ family: 'JetBrains Mono' }} }} }}
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});

// Toggle host cards
document.querySelectorAll('.host-banner').forEach(banner => {{
  banner.addEventListener('click', () => {{
    banner.closest('.host-card').classList.toggle('collapsed');
  }});
}});
</script>
</body>
</html>
"""


def _risk_color(level: str) -> str:
    return _RISK_COLORS.get(level, "#16a34a")


def _sev_badge(severity: str) -> str:
    col = _SEVERITY_COLORS.get(severity, "#666")
    return f'<span class="sev-badge" style="background:{col}">{severity}</span>'


def _build_stat_cards(scan_results: list) -> str:
    scores     = [h.get("risk_score", 0) for h in scan_results]
    max_score  = max(scores) if scores else 0
    avg_score  = round(sum(scores) / len(scores), 1) if scores else 0
    total_ports= sum(h.get("risk_metrics", {}).get("total_open_ports", 0) for h in scan_results)
    total_crit = sum(h.get("risk_metrics", {}).get("critical_cves", 0) for h in scan_results)
    total_high = sum(h.get("risk_metrics", {}).get("high_cves", 0) for h in scan_results)
    total_svc  = sum(len(h.get("services", [])) for h in scan_results)

    stats = [
        (len(scan_results), "Hosts Scanned",   "#00d4ff"),
        (max_score,         "Peak Risk Score",  "#dc2626"),
        (avg_score,         "Avg Risk Score",   "#ea580c"),
        (total_ports,       "Open Ports",       "#ca8a04"),
        (total_crit,        "Critical CVEs",    "#dc2626"),
        (total_high,        "High CVEs",        "#ea580c"),
        (total_svc,         "Total Services",   "#7c3aed"),
    ]
    return "".join(
        f'<div class="stat-card">'
        f'<div class="stat-val" style="color:{color}">{val}</div>'
        f'<div class="stat-label">{label}</div>'
        f'</div>'
        for val, label, color in stats
    )


def _build_host_card(host: dict, idx: int) -> str:
    ip         = host.get("ip", "?")
    score      = host.get("risk_score", 0)
    level      = host.get("risk_level", "LOW")
    device     = host.get("device_type", "Unknown")
    metrics    = host.get("risk_metrics", {})
    services   = host.get("services", [])
    mitre      = host.get("mitre_techniques", [])
    ai_summary = host.get("ai_analysis", "")
    risk_color = _risk_color(level)

    # Banner
    banner = f"""
    <div class="host-banner">
      <div>
        <span class="host-ip">{ip}</span>
        <span class="chip" style="margin-left:0.8rem">{device}</span>
      </div>
      <div class="host-meta">
        <span class="risk-badge" style="background:{risk_color}">{level}</span>
        <div>
          <div style="font-size:0.72rem;color:#64748b;margin-bottom:3px">Risk Score</div>
          <div class="score-bar-wrap">
            <div class="score-bar" style="width:{score}%;background:{risk_color}"></div>
          </div>
        </div>
        <span class="mono" style="font-size:1rem;color:{risk_color};font-weight:700">{score}/100</span>
        <span class="chip"> {metrics.get('total_open_ports',0)} ports</span>
        <span class="chip"> {metrics.get('critical_cves',0)} crit</span>
        <span class="toggle-icon">▼</span>
      </div>
    </div>"""

    # Info grid
    info_items = [
        ("MAC",          host.get("mac", "N/A")),
        ("Vendor",       host.get("vendor", "N/A")),
        ("OS",           host.get("os", "N/A")),
        ("Status",       host.get("status", "N/A")),
        ("Max CVSS",     str(metrics.get("max_cvss", 0))),
        ("Attack Surface", f"{metrics.get('attack_surface_idx', 0)}%"),
    ]
    info_grid = "".join(
        f'<div class="info-item"><label>{lbl}</label><span>{val}</span></div>'
        for lbl, val in info_items
    )

    # Services table
    if services:
        rows = ""
        for svc in services:
            vulns = svc.get("vulnerabilities", [])
            port  = f"{svc.get('port')}/{svc.get('protocol','tcp')}"
            desc  = svc.get("description", "")
            eol   = svc.get("eol_warnings", [])
            creds = svc.get("default_creds_hint", "")
            plain = svc.get("is_plaintext", False)

            flags = ""
            if eol:
                flags += '<span class="sev-badge" style="background:#7f1d1d;margin:1px">EOL</span> '
            if creds:
                flags += '<span class="sev-badge" style="background:#7c2d12;margin:1px" title="' + creds + '">DEF-CREDS</span> '
            if plain:
                flags += '<span class="sev-badge" style="background:#713f12;margin:1px">PLAINTEXT</span>'

            if vulns:
                cve_html = ""
                for v in vulns[:4]:
                    cve_html += (
                        f'{_sev_badge(v["severity"])} '
                        f'<span class="mono" style="font-size:0.78rem;color:#94a3b8">{v["cve_id"]}</span> '
                        f'<span style="color:#64748b;font-size:0.76rem">{v["description"][:60]}</span> '
                        f'<span style="color:#ea580c;font-size:0.76rem">(CVSS {v.get("cvss_score","?")})</span><br>'
                    )
            else:
                cve_html = '<span style="color:#475569;font-size:0.82rem">None detected</span>'

            rows += f"""
            <tr>
              <td class="mono">{port}</td>
              <td>{desc[:35]}</td>
              <td>{cve_html}</td>
              <td>{flags if flags else '<span style="color:#334155">—</span>'}</td>
            </tr>"""

        svc_table = f"""
        <p class="section-title">Open Services &amp; Vulnerabilities</p>
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>CVEs / Risks</th><th>Flags</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        svc_table = '<p style="color:#475569;font-size:0.85rem">No open services detected.</p>'

    # MITRE
    if mitre:
        mitre_html = "".join(
            f'<span class="mitre-tag">{t["technique_id"]}: {t["technique_name"]}</span>'
            for t in mitre[:10]
        )
        mitre_section = f'<p class="section-title">MITRE ATT&amp;CK Techniques</p><div>{mitre_html}</div>'
    else:
        mitre_section = ""

    # AI analysis
    if ai_summary and not ai_summary.startswith(""):
        ai_html = (
            f'<div class="ai-section">'
            f'<h4> AI Security Assessment</h4>'
            f'<div class="ai-content">{ai_summary}</div>'
            f'</div>'
        )
    else:
        ai_html = ""

    return f"""
  <div class="host-card" id="host-{idx}">
    {banner}
    <div class="host-body">
      <div class="info-grid">{info_grid}</div>
      {svc_table}
      {mitre_section}
      {ai_html}
    </div>
  </div>"""


def _build_chart_data(scan_results: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for h in scan_results:
        level = h.get("risk_level", "LOW")
        rc[level] = rc.get(level, 0) + 1

    color_map = {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ea580c",
        "MEDIUM":   "#ca8a04",
        "LOW":      "#16a34a",
    }
    return {
        "dist":   [rc["CRITICAL"], rc["HIGH"], rc["MEDIUM"], rc["LOW"]],
        "ips":    [h.get("ip", "?") for h in scan_results],
        "scores": [h.get("risk_score", 0) for h in scan_results],
        "colors": [color_map.get(h.get("risk_level", "LOW"), "#16a34a") for h in scan_results],
    }


def generate_html_report(scan_results: list, output_file: str = None) -> str:
    """Generate the HTML report and return its path."""
    output_file = _ensure_output_path(output_file, ".html")

    total_critical = sum(h.get("risk_metrics", {}).get("critical_cves", 0) for h in scan_results)
    total_ports    = sum(h.get("risk_metrics", {}).get("total_open_ports", 0) for h in scan_results)

    html = _HTML_TEMPLATE.format(
        tool          = TOOL_NAME,
        version       = VERSION,
        generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        host_count    = len(scan_results),
        total_critical= total_critical,
        total_ports   = total_ports,
        stat_cards    = _build_stat_cards(scan_results),
        host_cards    = "".join(_build_host_card(h, i) for i, h in enumerate(scan_results)),
        chart_data_json = json.dumps(_build_chart_data(scan_results)),
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    log_message(f"HTML report written to {output_file}")
    print(f"[+] HTML report saved to: {output_file}")
    return output_file
