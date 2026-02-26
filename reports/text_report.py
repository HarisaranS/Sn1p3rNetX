from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.rule import Rule
from rich import box

console = Console(legacy_windows=False)
REPORT_WIDTH = 40

def generate_text_report(scan_results):
    """
    Outputs a human-readable summary to the terminal.
    """
    for host in scan_results:
        # 1. Basic Info
        console.print(f"\n[bold green]Target Host:[/bold green] [cyan]{host.get('ip')}[/cyan]")
        if host.get('mac') and host.get('mac') != "MAC Not Found":
            console.print(f"MAC Address: [bold]{host.get('mac')}[/bold] ({host.get('vendor')})")
        if host.get('os') and host.get('os') != "OS Detection Uncertain":
            console.print(f"Operating System: [bold yellow]{host.get('os')}[/bold yellow]")
        console.print("-" * REPORT_WIDTH)
        
        # 2. Risk Info
        score = host.get('risk_score', 0)
        level = host.get('risk_level', 'UNKNOWN')
        metrics = host.get('risk_metrics', {})
        
        if level == "CRITICAL":
            color = "bold red"
        elif level == "HIGH":
            color = "red"
        elif level == "MEDIUM":
            color = "yellow"
        else:
            color = "green"
            
        console.print(f"Open Ports: [bold]{metrics.get('total_open_ports', 0)}[/bold]")
        console.print(f"Critical CVEs: [bold]{metrics.get('critical_cves', 0)}[/bold]")
        console.print(f"Risk Score: [{color}]{score}[/{color}]")
        console.print(f"Risk Level: [{color}]{level}[/{color}]\n")
        
        # 3. Services Table
        services = host.get('services', [])
        if services:
            table = Table(show_header=True, header_style="bold magenta", box=None, expand=False)
            table.add_column("Port/Proto", style="cyan", no_wrap=True, justify="left")
            table.add_column("Service", style="white", justify="left")
            table.add_column("Vulnerabilities", style="yellow", justify="left")
            
            for s in services:
                vulns = s.get('vulnerabilities', [])
                vuln_str = "\n".join([f"[{v['severity']}] {v['cve_id']}" for v in vulns]) if vulns else "None"
                table.add_row(f"{s.get('port')}/{s.get('protocol')}", s.get('description'), vuln_str)
                
            console.print(table)
            console.print()
            
        # 4. AI Analysis text
        ai_summary = host.get('ai_analysis')
        if ai_summary:
            md = Markdown(ai_summary)
            # Use 40-char line for AI Analysis
            console.print(f"\n[bold cyan]" + "-" * 10 + " AI Analysis Report " + "-" * 10 + "[/bold cyan]")
            console.print(md)
            console.print(f"[bold cyan]" + "-" * REPORT_WIDTH + "[/bold cyan]\n")
