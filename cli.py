#!/usr/bin/env python3
import argparse
import sys
import json
import pyfiglet
from rich.console import Console
from rich.status import Status
from rich.rule import Rule
from rich import box

from config import VERSION
from core.utils import check_disclaimer, get_scan_history, save_scan_history
from core.scanner import scan_network_range
from core.cve_lookup import enrich_services_with_cves
from core.risk_engine import process_risk_for_hosts
from core.ai_analyzer import generate_ai_analysis
from reports.text_report import generate_text_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report

console = Console(legacy_windows=False)

def print_banner():
    """Print the Sn1p3rNetX ASCII banner."""
    ascii_banner = pyfiglet.figlet_format("Sn1p3rNetX")
    console.print(f"[bold magenta]{ascii_banner}[/bold magenta]")
    console.print(f"[bold cyan]AI-Powered Network Risk Intelligence v{VERSION}[/bold cyan]")
    console.print("-" * 40)

def cmd_scan(args):
    """Perform a pure scan without AI."""
    console.print(f"[cyan]Starting Scan on target:[/cyan] {args.target}")
    
    with console.status("[bold yellow]Scanning network...[/bold yellow]", spinner="dots") as status:
        def callback(msg):
            status.update(f"[bold yellow]{msg}[/bold yellow]")
            
        scan_res = scan_network_range(args.target, aggressive=args.aggressive, callback=callback)
    
    if "error" in scan_res:
        console.print(f"[bold red]Scan Failed:[/bold red] {scan_res['error']}")
        sys.exit(1)
        
    hosts = scan_res.get("results", [])
    if not hosts:
        console.print("[yellow]No interactive hosts found.[/yellow]")
        return
        
    # Map CVEs and Risk
    hosts = enrich_services_with_cves(hosts)
    hosts = process_risk_for_hosts(hosts)
    
    # Save History
    if hosts:
        save_scan_history(args.target, hosts)
        
    # Report output
    generate_text_report(hosts)
    if args.json:
        generate_json_report(hosts)

def cmd_analyze(args):
    """Analyze a previous JSON scan dump using AI."""
    try:
        with open(args.json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Failed to load file:[/bold red] {e}")
        sys.exit(1)
        
    with console.status("[bold cyan]Running AI Contextual Analysis...[/bold cyan]", spinner="bouncingBar"):
        for host in data:
            # Avoid sending too big payload, send only relevant data
            analysis_payload = {
                "ip": host.get("ip"),
                "os": host.get("os"),
                "risk_score": host.get("risk_score"),
                "risk_level": host.get("risk_level"),
                "services": host.get("services", [])
            }
            ai_summary = generate_ai_analysis(analysis_payload)
            host['ai_analysis'] = ai_summary
        
    generate_text_report(data)
    
    if args.pdf:
        generate_pdf_report(data)

def cmd_fullscan(args):
    """Perform full scan, enrichment, and AI analysis."""
    console.print(f"[bold magenta]Starting Full AI Pipeline Scan on:[/bold magenta] {args.target}")
    
    with console.status("[bold yellow]Scanning network...[/bold yellow]", spinner="dots") as status:
        def callback(msg):
            status.update(f"[bold yellow]{msg}[/bold yellow]")
            
        scan_res = scan_network_range(args.target, aggressive=True, callback=callback)
    if "error" in scan_res:
        console.print(f"[bold red]Scan Failed:[/bold red] {scan_res['error']}")
        sys.exit(1)
        
    hosts = scan_res.get("results", [])
    
    hosts = enrich_services_with_cves(hosts)
    hosts = process_risk_for_hosts(hosts)
    
    with console.status("[bold cyan]Running AI Contextual Analysis...[/bold cyan]", spinner="bouncingBar"):
        for host in hosts:
            analysis_payload = {
                "ip": host.get("ip"),
                "os": host.get("os"),
                "risk_score": host.get("risk_score"),
                "risk_level": host.get("risk_level"),
                "services": host.get("services", [])
            }
            host['ai_analysis'] = generate_ai_analysis(analysis_payload)
        
    if hosts:
        save_scan_history(args.target, hosts)
        
    generate_text_report(hosts)
    
    if args.json:
        generate_json_report(hosts)
    if args.pdf:
        generate_pdf_report(hosts)

def cmd_history(args):
    """Display previous scan history."""
    rows = get_scan_history()
    if not rows:
        console.print("[yellow]No scan history found.[/yellow]")
        return
        
    table = Table(title="Scan History", box=box.SIMPLE, expand=False)
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Target", style="white")
    table.add_column("Hosts", style="green", justify="center")
    table.add_column("Avg Risk", style="yellow", justify="center")
    
    for row in rows[:50]: # limit to last 50
        ts, target, count, avg_risk = row
        avg_risk_str = f"{avg_risk:.1f}" if avg_risk is not None else "0.0"
        table.add_row(ts, target, str(count), avg_risk_str)
        
    console.print(table)

def main():
    check_disclaimer()
    
    from core.scanner import is_root
    if not is_root():
        console.print("[bold yellow]Warning: Running without root privileges. OS detection and some advanced scanning features will be disabled.[/bold yellow]")
        console.print("[bold yellow]To enable full analysis, run with: sudo -E python3 cli.py ...[/bold yellow]")
        console.print("-" * 40)
    
    parser = argparse.ArgumentParser(description=f"Sn1p3rNetX+ v{VERSION} - AI-Powered Network Risk Intelligence CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # 1. scan command
    p_scan = subparsers.add_parser("scan", help="Perform a standard network vulnerability scan")
    p_scan.add_argument("target", help="IP, CIDR, or Domain to scan")
    p_scan.add_argument("--aggressive", action="store_true", help="Enable aggressive scan options")
    p_scan.add_argument("--json", action="store_true", help="Output results to JSON file")
    
    # 2. analyze command
    p_analyze = subparsers.add_parser("analyze", help="Analyze existing JSON scan results with AI")
    p_analyze.add_argument("json_file", help="Path to json file")
    p_analyze.add_argument("--pdf", action="store_true", help="Export analysis as PDF report")
    
    # 3. fullscan command
    p_fullscan = subparsers.add_parser("fullscan", help="Run scan -> CVE -> Score -> AI analysis pipeline")
    p_fullscan.add_argument("target", help="IP, CIDR, or Domain to scan")
    p_fullscan.add_argument("--json", action="store_true", help="Export to JSON")
    p_fullscan.add_argument("--pdf", action="store_true", help="Export to PDF")
    
    # 4. history command
    subparsers.add_parser("history", help="View past scan logs and risk scores")
    
    args = parser.parse_args()
    
    print_banner()
    console.print(f"[bold green]Initialization Complete.[/bold green]")
    
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "fullscan":
        cmd_fullscan(args)
    elif args.command == "history":
        cmd_history(args)

if __name__ == "__main__":
    main()
