from fpdf import FPDF
import json
from datetime import datetime
import os

class PDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'Sn1p3rNetX+ Security Report', align='C', new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def generate_pdf_report(scan_results, output_file=None):
    if not output_file:
        output_file = f"sn1p3rnetx_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)

    for host in scan_results:
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, f"Target: {host.get('ip')}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", size=12)
        score = host.get('risk_score', 0)
        level = host.get('risk_level', 'UNKNOWN')
        metrics = host.get('risk_metrics', {})
        
        pdf.cell(0, 8, f"Status: {host.get('status', 'Unknown')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"MAC / Vendor: {host.get('mac')} / {host.get('vendor')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"OS: {host.get('os')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Open Ports: {metrics.get('total_open_ports', 0)}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, f"Risk Score: {score} ({level})", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Services Table
        services = host.get('services', [])
        if services:
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(40, 10, "Port/Proto", border=1)
            pdf.cell(80, 10, "Service", border=1)
            pdf.cell(70, 10, "Vulnerabilities", border=1, new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", size=10)
            for s in services:
                vulns = s.get('vulnerabilities', [])
                vuln_count = len(vulns)
                vuln_str = f"{vuln_count} found" if vuln_count > 0 else "None"
                
                # MultiCell for wrapping might be needed if services list gets long
                # We'll stick to a simple representation for now
                port_str = f"{s.get('port')}/{s.get('protocol')}"
                desc_str = str(s.get('description'))[:35]
                
                pdf.cell(40, 10, port_str, border=1)
                pdf.cell(80, 10, desc_str, border=1)
                pdf.cell(70, 10, vuln_str, border=1, new_x="LMARGIN", new_y="NEXT")
                
        # AI Summary
        ai_summary = host.get('ai_analysis')
        if ai_summary:
            pdf.ln(5)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "AI Executive Summary & Recommendations:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", size=10)
            pdf.multi_cell(0, 6, str(ai_summary).encode('utf-8', 'ignore').decode('utf-8'))
            
        pdf.add_page()
            
    try:
        pdf.output(output_file)
        print(f"[+] PDF report saved to: {output_file}")
    except Exception as e:
        print(f"[-] Failed to generate PDF: {e}")
