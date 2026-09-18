#!/usr/bin/env python3
"""
Sn1p3rNetX v3.0 — AI-Powered Network Risk Intelligence CLI
Enterprise-grade network vulnerability scanner with AI analysis.
"""

import argparse
import sys
import json
import signal
import pyfiglet
from rich.console import Console
from rich.table   import Table
from rich.rule    import Rule
from rich         import box

from config import VERSION
from core.utils        import check_disclaimer, get_scan_history, save_scan_history, log_message
from core.scanner      import scan_network_range, is_root
from core.cve_lookup   import enrich_services_with_cves
from core.service_intel import enrich_services_with_intel
from core.risk_engine  import process_risk_for_hosts
from core.ai_analyzer  import generate_ai_analysis
from reports.text_report import generate_text_report
from reports.json_report import generate_json_report
from reports.pdf_report  import generate_pdf_report
from reports.html_report import generate_html_report
from core.dashboard import run_dashboard
from core.drift_detector import diff_target, format_drift_report, get_latest_two_scans
from core.compliance import run_all_frameworks
from core.remediation import generate_remediation_script
from core.attack_story import generate_attack_story, format_attack_story
from core.business_risk import generate_executive_brief
from core.watchdog import start_watchdog

console = Console(legacy_windows=False)


# ── Graceful Ctrl+C ────────────────────────────────────────────────────────────
def _sigint_handler(sig, frame):
    console.print("\n\n[bold yellow]  Scan interrupted by user (Ctrl+C).[/bold yellow]")
    console.print("[dim]Partial results (if any) were not saved.[/dim]")
    sys.exit(0)

signal.signal(signal.SIGINT, _sigint_handler)


# ── Banner ─────────────────────────────────────────────────────────────────────
def print_banner():
    ascii_banner = pyfiglet.figlet_format("Sn1p3rNetX", font="slant")
    console.print(f"[bold magenta]{ascii_banner}[/bold magenta]")
    console.print(f"[bold cyan]AI-Powered Network Risk Intelligence v{VERSION}[/bold cyan]")
    console.print("[dim]Enterprise Security Scanner — For Authorised Use Only[/dim]")
    console.print("-" * 50)


# ── Pipeline helpers ────────────────────────────────────────────────────────────
def _run_scan(target: str, aggressive: bool, mode: str,
              threads: int, timeout: int, callback=None) -> list:
    """Execute scan → CVE enrichment → service intel → risk scoring."""
    scan_res = scan_network_range(
        target, mode=mode, aggressive=aggressive,
        threads=threads, timeout=timeout, callback=callback,
    )

    if "error" in scan_res:
        console.print(f"[bold red]Scan Failed:[/bold red] {scan_res['error']}")
        sys.exit(1)

    hosts = scan_res.get("results", [])
    if not hosts:
        console.print("[yellow]No interactive hosts found.[/yellow]")
        sys.exit(0)

    hosts = enrich_services_with_cves(hosts)
    hosts = enrich_services_with_intel(hosts)
    hosts = process_risk_for_hosts(hosts)
    return hosts


def _run_ai(hosts: list) -> list:
    """Attach AI analysis to each host."""
    with console.status("[bold cyan] Running AI Analysis…[/bold cyan]", spinner="bouncingBar"):
        for host in hosts:
            payload = {
                "ip":              host.get("ip"),
                "os":              host.get("os"),
                "device_type":     host.get("device_type"),
                "risk_score":      host.get("risk_score"),
                "risk_level":      host.get("risk_level"),
                "risk_metrics":    host.get("risk_metrics"),
                "services":        host.get("services", []),
                "mitre_techniques":host.get("mitre_techniques", []),
            }
            host["ai_analysis"] = generate_ai_analysis(payload)
    return hosts


def _output_reports(hosts: list, args) -> None:
    """Write the requested report formats."""
    generate_text_report(hosts)

    if getattr(args, "json", False):
        generate_json_report(hosts)
    if getattr(args, "html", False):
        generate_html_report(hosts)
    if getattr(args, "pdf", False):
        generate_pdf_report(hosts)


# ── Sub-commands ───────────────────────────────────────────────────────────────

def cmd_scan(args):
    """Fast scan — no AI."""
    console.print(f"[cyan]Starting Scan on target:[/cyan] [bold]{args.target}[/bold]")

    with console.status("[bold yellow]Scanning network…[/bold yellow]", spinner="dots") as status:
        hosts = _run_scan(
            args.target,
            aggressive = args.aggressive,
            mode       = args.mode,
            threads    = args.threads,
            timeout    = args.timeout,
            callback   = lambda m: status.update(f"[bold yellow]{m}[/bold yellow]"),
        )

    if hosts:
        save_scan_history(args.target, hosts, scan_mode=args.mode)

    _output_reports(hosts, args)


def cmd_fullscan(args):
    """Full pipeline: scan → CVE → risk → AI → report."""
    console.print(f"[bold magenta] Full AI Pipeline Scan:[/bold magenta] [bold]{args.target}[/bold]")

    with console.status("[bold yellow]Scanning…[/bold yellow]", spinner="dots") as status:
        hosts = _run_scan(
            args.target,
            aggressive = True,
            mode       = args.mode,
            threads    = args.threads,
            timeout    = args.timeout,
            callback   = lambda m: status.update(f"[bold yellow]{m}[/bold yellow]"),
        )

    hosts = _run_ai(hosts)

    if hosts:
        save_scan_history(args.target, hosts, scan_mode=args.mode)

    _output_reports(hosts, args)


def cmd_analyze(args):
    """AI analysis of a previously saved JSON scan file."""
    try:
        with open(args.json_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
            # Support both wrapped (v3 schema) and bare list formats
            data = raw.get("hosts", raw) if isinstance(raw, dict) else raw
    except Exception as e:
        console.print(f"[bold red]Failed to load file:[/bold red] {e}")
        sys.exit(1)

    # Re-enrich (in case it was a v2 JSON without service_intel or risk_engine data)
    data = enrich_services_with_cves(data)
    data = enrich_services_with_intel(data)
    data = process_risk_for_hosts(data)

    data = _run_ai(data)
    _output_reports(data, args)


def cmd_history(args):
    """Display scan history from SQLite."""
    rows = get_scan_history()
    if not rows:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title=" Scan History", box=box.ROUNDED, expand=False,
                  header_style="bold magenta")
    table.add_column("Timestamp",  style="cyan",   no_wrap=True, width=22)
    table.add_column("Target",     style="white",  width=22)
    table.add_column("Mode",       style="dim",    width=8)
    table.add_column("Hosts",      style="green",  justify="center", width=7)
    table.add_column("Avg Risk",   style="yellow", justify="center", width=10)

    for row in rows[:50]:
        ts, target, count, avg_risk, mode = row
        avg_str = f"{avg_risk:.1f}" if avg_risk is not None else "0.0"
        table.add_row(ts[:19], target, mode or "tcp", str(count), avg_str)

    console.print(table)


def _get_latest_host(target: str) -> dict:
    _, current = get_latest_two_scans(target)
    if not current:
        console.print(f"[bold red]No scan history found for {target}. Run fullscan first.[/bold red]")
        sys.exit(1)
    return current


def cmd_dashboard(args):
    """Launch interactive real-time dashboard."""
    host = _get_latest_host(args.target)
    run_dashboard([host])


def cmd_drift(args):
    """Compare latest scan with previous scan."""
    diff = diff_target(args.target)
    console.print(format_drift_report(diff))


def cmd_comply(args):
    """Run compliance mapper."""
    host = _get_latest_host(args.target)
    results = run_all_frameworks(host)
    for res in results:
        color = "green" if res["grade"] == "A" else "red"
        console.print(f"\n[bold {color}]{res['framework']} — Grade: {res['grade']} ({res['score_pct']}%)[/bold {color}]")
        for f in res["failed"]:
            console.print(f"   [{f['id']}] {f['desc']}")
        for p in res["passed"]:
            console.print(f"   [{p['id']}] {p['desc']}")


def cmd_remediate(args):
    """Generate exact remediation shell commands."""
    host = _get_latest_host(args.target)
    script = generate_remediation_script(host)
    console.print(f"[bold cyan]Remediation Script for {args.target}[/bold cyan]")
    console.print(f"```bash\n{script}\n```")


def cmd_story(args):
    """Generate AI Attack Story."""
    host = _get_latest_host(args.target)
    story = generate_attack_story(host)
    console.print(format_attack_story(story))


def cmd_business(args):
    """Generate Business Risk executive brief."""
    host = _get_latest_host(args.target)
    brief = generate_executive_brief(host)
    console.print(f"[bold yellow]{brief}[/bold yellow]")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    check_disclaimer()

    if not is_root():
        console.print("[bold yellow]  Running without root privileges.[/bold yellow]")
        console.print("[dim]  OS detection & SYN stealth disabled. Using TCP connect scan (-sT).[/dim]")
        console.print("[dim]  For full capability: sudo -E python3 cli.py …[/dim]")
        console.print("-" * 50)

    parser = argparse.ArgumentParser(
        description=f"Sn1p3rNetX v{VERSION} — AI-Powered Network Risk Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Fast network scan (no AI)")
    p_scan.add_argument("target",       help="IP, CIDR, hostname, or 'auto'")
    p_scan.add_argument("--aggressive", action="store_true", help="Enable -A (banner, scripts)")
    p_scan.add_argument("--mode",       default="tcp", choices=["tcp","udp","both"])
    p_scan.add_argument("--threads",    type=int, default=20, metavar="N")
    p_scan.add_argument("--timeout",    type=int, default=120, metavar="SEC")
    p_scan.add_argument("--json",       action="store_true", help="Save JSON report")
    p_scan.add_argument("--html",       action="store_true", help="Save HTML report")
    p_scan.add_argument("--pdf",        action="store_true", help="Save PDF report")

    # ── fullscan ──────────────────────────────────────────────────────────────
    p_full = sub.add_parser("fullscan", help="Scan + CVE + Risk + AI pipeline")
    p_full.add_argument("target",       help="IP, CIDR, hostname, or 'auto'")
    p_full.add_argument("--mode",       default="tcp", choices=["tcp","udp","both"])
    p_full.add_argument("--threads",    type=int, default=20, metavar="N")
    p_full.add_argument("--timeout",    type=int, default=120, metavar="SEC")
    p_full.add_argument("--json",       action="store_true")
    p_full.add_argument("--html",       action="store_true")
    p_full.add_argument("--pdf",        action="store_true")

    # ── analyze ───────────────────────────────────────────────────────────────
    p_ana = sub.add_parser("analyze", help="AI analysis of existing JSON report")
    p_ana.add_argument("json_file", help="Path to JSON report file")
    p_ana.add_argument("--json",    action="store_true")
    p_ana.add_argument("--html",    action="store_true")
    p_ana.add_argument("--pdf",     action="store_true")

    # ── history ───────────────────────────────────────────────────────────────
    sub.add_parser("history", help="View scan history")

    # ── NSIP Commands ─────────────────────────────────────────────────────────
    p_dash = sub.add_parser("dashboard", help="Launch live interactive TUI dashboard")
    p_dash.add_argument("target", help="Target IP")

    p_drift = sub.add_parser("drift", help="Detect changes since last scan")
    p_drift.add_argument("target", help="Target IP")

    p_comply = sub.add_parser("comply", help="Map findings to compliance frameworks")
    p_comply.add_argument("target", help="Target IP")

    p_rem = sub.add_parser("remediate", help="Generate shell remediation script")
    p_rem.add_argument("target", help="Target IP")

    p_story = sub.add_parser("story", help="Generate Attack Story narrative")
    p_story.add_argument("target", help="Target IP")

    p_biz = sub.add_parser("business", help="Translate to business risk/dollars")
    p_biz.add_argument("target", help="Target IP")


    args = parser.parse_args()

    print_banner()
    console.print(f"[bold green] Initialization Complete.[/bold green]")

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "fullscan":
        cmd_fullscan(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "history":
        cmd_history(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "drift":
        cmd_drift(args)
    elif args.command == "comply":
        cmd_comply(args)
    elif args.command == "remediate":
        cmd_remediate(args)
    elif args.command == "story":
        cmd_story(args)
    elif args.command == "business":
        cmd_business(args)


if __name__ == "__main__":
    main()
