"""
text_report.py — Rich terminal report renderer.

Produces a full-featured, colour-coded terminal report with:
  • Host header panel with device classification
  • Risk score gauge (progress bar)
  • Services table with CVE details, CVSS scores, EOL warnings
  • MITRE ATT&CK technique table
  • AI analysis in Markdown
  • Network topology map
  • Consolidated network summary
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.rule import Rule
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text
from rich import box
from rich.columns import Columns

console = Console(legacy_windows=False)


def _risk_color(level: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }.get(level, "white")


def _severity_badge(sev: str) -> str:
    return {
        "CRITICAL": "[bold white on red] CRITICAL [/bold white on red]",
        "HIGH":     "[bold white on dark_orange] HIGH [/bold white on dark_orange]",
        "MEDIUM":   "[bold black on yellow] MEDIUM [/bold black on yellow]",
        "LOW":      "[bold white on green] LOW [/bold white on green]",
    }.get(sev, sev)


def _risk_gauge(score: int, level: str) -> str:
    """Build a compact visual gauge string."""
    filled  = int(score / 5)     # 20 blocks max
    empty   = 20 - filled
    color   = _risk_color(level)
    bar     = f"[{color}]{'█' * filled}[/{color}]{'░' * empty}"
    return f"{bar}  [{color}]{score}/100  {level}[/{color}]"


def _print_host_header(host: dict):
    ip          = host.get("ip", "?")
    mac         = host.get("mac", "")
    vendor      = host.get("vendor", "")
    os_det      = host.get("os", "OS Detection Uncertain")
    status      = host.get("status", "")
    device_type = host.get("device_type", "Unknown")
    risk_level  = host.get("risk_level", "LOW")
    score       = host.get("risk_score", 0)
    color       = _risk_color(risk_level)

    mac_line = f"  MAC: [bold]{mac}[/bold] ({vendor})" if mac and mac != "MAC Not Found" else ""
    os_line  = f"  OS:  [yellow]{os_det}[/yellow]" if os_det != "OS Detection Uncertain" else ""

    content = (
        f"[bold cyan]  {ip}[/bold cyan]   [{color}]{status}[/{color}]\n"
        f"  Device: [magenta]{device_type}[/magenta]\n"
        + (mac_line + "\n" if mac_line else "")
        + (os_line  + "\n" if os_line  else "")
        + f"\n  Risk: {_risk_gauge(score, risk_level)}"
    )

    console.print(Panel(content, title=f"[bold]Host Report — {ip}[/bold]",
                         border_style=color, padding=(0, 1), expand=False, box=box.SIMPLE))


def _print_services_table(host: dict):
    services = host.get("services", [])
    if not services:
        console.print("  [dim]No open services detected.[/dim]\n")
        return

    table = Table(
        title="Open Services & Vulnerabilities",
        box=None,
        header_style="bold magenta",
        show_lines=True,
        expand=False,
    )
    table.add_column("Port",          style="cyan")
    table.add_column("Service",       style="white")
    table.add_column("CVE / Risk",    style="yellow", overflow="fold")
    table.add_column("CVSS",          style="bold",   justify="center")
    table.add_column("Flags",         style="dim")

    for svc in services:
        port        = svc.get("port", "")
        proto       = svc.get("protocol", "tcp")
        desc        = svc.get("description", "")
        vulns       = svc.get("vulnerabilities", [])
        max_cvss    = svc.get("max_cvss", 0.0)
        eol         = svc.get("eol_warnings", [])
        creds_hint  = svc.get("default_creds_hint")
        plaintext   = svc.get("is_plaintext", False)

        # CVE text
        if vulns:
            vuln_lines = []
            for v in vulns[:4]:
                badge = _severity_badge(v["severity"])
                vuln_lines.append(f"{badge} {v['cve_id']}\n  {v['description'][:50]}")
            vuln_str = "\n".join(vuln_lines)
        else:
            vuln_str = "[dim]None detected[/dim]"

        # Flags
        flags = []
        if eol:
            flags.append("[red]EOL[/red]")
        if creds_hint:
            flags.append("[red]DEF-CREDS[/red]")
        if plaintext:
            flags.append("[yellow]PLAINTEXT[/yellow]")

        cvss_str = f"[red]{max_cvss:.1f}[/red]" if max_cvss >= 7.0 else (
                   f"[yellow]{max_cvss:.1f}[/yellow]" if max_cvss >= 4.0 else
                   f"[green]{max_cvss:.1f}[/green]" if max_cvss > 0 else "[dim]—[/dim]")

        table.add_row(
            f"{port}/{proto}",
            desc[:24],
            vuln_str,
            cvss_str,
            " ".join(flags) if flags else "[dim]—[/dim]",
        )

        # EOL / creds warnings inline
        if eol:
            for w in eol[:1]:
                table.add_row("", "[dim] EOL:[/dim]", f"[red]{w[:60]}[/red]", "", "")
        if creds_hint:
            table.add_row("", "[dim] Defaults:[/dim]", f"[red]{creds_hint}[/red]", "", "")

    console.print(table)


def _print_mitre_table(host: dict):
    techniques = host.get("mitre_techniques", [])
    if not techniques:
        return

    table = Table(
        title="MITRE ATT&CK Techniques",
        box=None,
        header_style="bold red",
        expand=False,
    )
    table.add_column("Technique ID", style="bold cyan")
    table.add_column("Name",         style="white", overflow="fold")

    for t in techniques[:10]:
        table.add_row(t["technique_id"], t["technique_name"])

    console.print(table)
    console.print()


def _print_ai_analysis(host: dict):
    ai = host.get("ai_analysis")
    if not ai:
        return
    console.print(Rule("[bold cyan]AI Security Assessment[/bold cyan]", style="cyan"))
    console.print(Markdown(ai))
    console.print(Rule(style="cyan"))
    console.print()


def _print_network_summary(scan_results: list):
    """Print an overall network summary panel after all individual reports."""
    from core.topology import get_subnet_summary, build_ascii_topology

    if len(scan_results) < 1:
        return

    console.print()
    console.print(Rule("[bold magenta]Network Summary[/bold magenta]", style="magenta"))
    console.print()

    # Print ASCII topology
    topo = build_ascii_topology(scan_results)
    console.print(topo)
    console.print()

    summary = get_subnet_summary(scan_results)
    rc = summary.get("risk_distribution", {})

    tbl = Table(box=None, header_style="bold", expand=False)
    tbl.add_column("Metric",       style="cyan")
    tbl.add_column("Value",        style="white")

    tbl.add_row("Total Hosts",          str(summary.get("host_count", 0)))
    tbl.add_row("Average Risk Score",   str(summary.get("avg_risk_score", 0)))
    tbl.add_row("Total Open Ports",     str(summary.get("total_open_ports", 0)))
    tbl.add_row("Total HIGH+ CVEs",     str(summary.get("total_high_cves", 0)))
    tbl.add_row(" CRITICAL Hosts",   str(rc.get("CRITICAL", 0)))
    tbl.add_row(" HIGH Hosts",        str(rc.get("HIGH", 0)))
    tbl.add_row(" MEDIUM Hosts",      str(rc.get("MEDIUM", 0)))
    tbl.add_row(" LOW Hosts",         str(rc.get("LOW", 0)))

    device_bd = summary.get("device_breakdown", {})
    for dt, count in device_bd.items():
        tbl.add_row(f"  {dt}", str(count))

    console.print(tbl)


def generate_text_report(scan_results: list, show_topology: bool = True):
    """Main entry point — renders the full terminal report."""
    if not scan_results:
        console.print("[yellow]No scan results to report.[/yellow]")
        return

    for host in scan_results:
        _print_host_header(host)
        console.print()
        _print_services_table(host)
        console.print()
        _print_mitre_table(host)
        _print_ai_analysis(host)

    if show_topology and len(scan_results) > 0:
        _print_network_summary(scan_results)
