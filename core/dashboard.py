"""
dashboard.py — Real-time interactive terminal security dashboard.

A live Rich-powered TUI (Terminal User Interface) that renders a full-screen
security operations view for a network. Think `htop` but for security.

Usage:
    from core.dashboard import run_dashboard
    run_dashboard(hosts)
"""

from __future__ import annotations
import time
import threading
from datetime import datetime
from typing import Callable

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich import box

console = Console()

_RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

_RISK_DOTS = {
    "CRITICAL": "",
    "HIGH":     "",
    "MEDIUM":   "",
    "LOW":      "",
}


def _risk_bar(score: int, level: str, width: int = 20) -> Text:
    filled = int(score / 100 * width)
    empty  = width - filled
    color  = _RISK_COLORS.get(level, "white")
    t = Text()
    t.append("█" * filled, style=color)
    t.append("░" * empty,  style="dim")
    t.append(f"  {score}/100 {level}", style=color)
    return t


def _make_header(hosts: list, scan_time: str) -> Panel:
    total   = len(hosts)
    scores  = [h.get("risk_score", 0) for h in hosts]
    avg     = round(sum(scores) / total, 1) if scores else 0
    crit    = sum(1 for h in hosts if h.get("risk_level") == "CRITICAL")
    ports   = sum(h.get("risk_metrics", {}).get("total_open_ports", 0) for h in hosts)
    cves    = sum(h.get("risk_metrics", {}).get("critical_cves", 0) for h in hosts)

    g = Table.grid(expand=True)
    g.add_column(ratio=1)
    g.add_column(ratio=1)
    g.add_column(ratio=1)
    g.add_column(ratio=1)
    g.add_column(ratio=1)
    g.add_row(
        _stat_cell("", str(total),  "Hosts"),
        _stat_cell("", f"{avg}",    "Avg Risk"),
        _stat_cell("", str(crit),   "Critical"),
        _stat_cell("", str(ports),  "Open Ports"),
        _stat_cell("", str(cves),   "Crit CVEs"),
    )

    title_text = Text()
    title_text.append("  Sn1p3rNetX", style="bold cyan")
    title_text.append(" │ ", style="dim")
    title_text.append("Network Security Intelligence", style="bold white")
    title_text.append("  │  ", style="dim")
    title_text.append(f"Last scan: {scan_time}", style="dim")
    title_text.append("  │  ", style="dim")
    title_text.append(f"[LIVE]", style="bold blink red")

    return Panel(g, title=title_text, border_style="cyan", padding=(0, 1))


def _stat_cell(icon: str, value: str, label: str) -> Text:
    t = Text(justify="center")
    t.append(f"\n{icon}  ", style="dim")
    t.append(value + "\n", style="bold cyan")
    t.append(label + "\n", style="dim")
    return t


def _make_host_table(hosts: list) -> Panel:
    table = Table(
        box=None,
        header_style="bold magenta",
        show_lines=True,
        expand=True,
        min_width=60,
    )
    table.add_column("IP",          style="bold cyan")
    table.add_column("Device",      style="white")
    table.add_column("Risk",        justify="center")
    table.add_column("Score")
    table.add_column("Ports",       justify="center")
    table.add_column("Crit CVEs",   justify="center")
    table.add_column("OS",          style="dim")

    sorted_hosts = sorted(hosts, key=lambda h: h.get("risk_score", 0), reverse=True)
    for host in sorted_hosts:
        level   = host.get("risk_level", "LOW")
        score   = host.get("risk_score", 0)
        metrics = host.get("risk_metrics", {})
        dot     = _RISK_DOTS.get(level, "")

        level_cell = Text(f"{dot} {level}", style=_RISK_COLORS.get(level, "white"))
        bar_cell   = _risk_bar(score, level, width=16)
        os_str     = (host.get("os") or "Unknown")[:18]
        device     = host.get("device_type", "Unknown")[:22]

        table.add_row(
            host.get("ip", "?"),
            device,
            level_cell,
            bar_cell,
            str(metrics.get("total_open_ports", 0)),
            str(metrics.get("critical_cves", 0)),
            os_str,
        )

    return Panel(table, title="[bold]  Host Intelligence[/bold]", border_style="blue")


def _make_cve_feed(hosts: list) -> Panel:
    """Top critical CVEs across all hosts."""
    all_vulns = []
    for host in hosts:
        for svc in host.get("services", []):
            for v in svc.get("vulnerabilities", []):
                if v.get("severity") in ("CRITICAL", "HIGH"):
                    all_vulns.append({
                        "ip":    host.get("ip"),
                        "port":  svc.get("port"),
                        "cve":   v.get("cve_id"),
                        "sev":   v.get("severity"),
                        "cvss":  v.get("cvss_score", 0),
                        "desc":  v.get("description", "")[:45],
                    })

    all_vulns.sort(key=lambda x: x["cvss"], reverse=True)

    table = Table(box=None, header_style="bold red", expand=True, show_lines=False)
    table.add_column("IP",     style="cyan")
    table.add_column("Port",   style="white", justify="center")
    table.add_column("CVE",    style="bold")
    table.add_column("CVSS",   justify="center")
    table.add_column("Description", style="dim", overflow="fold")

    for v in all_vulns[:10]:
        sev = v["sev"]
        color = "red" if sev == "CRITICAL" else "orange3"
        cve_cell = Text(v["cve"], style=f"bold {color}")
        cvss_cell = Text(f"{v['cvss']:.1f}", style=color)
        table.add_row(v["ip"], str(v["port"]), cve_cell, cvss_cell, v["desc"])

    if not all_vulns:
        table.add_row("—", "—", "No critical CVEs", "—", "—")

    return Panel(table, title="[bold red] Critical CVE Feed[/bold red]", border_style="red")


def _make_mitre_panel(hosts: list) -> Panel:
    """Aggregated MITRE ATT&CK techniques."""
    seen = {}
    for host in hosts:
        for t in host.get("mitre_techniques", []):
            tid = t["technique_id"]
            if tid not in seen:
                seen[tid] = {"id": tid, "name": t["technique_name"], "hosts": 0}
            seen[tid]["hosts"] += 1

    techniques = sorted(seen.values(), key=lambda x: x["hosts"], reverse=True)

    table = Table(box=None, expand=True, header_style="bold magenta")
    table.add_column("Technique",    style="bold cyan")
    table.add_column("Name",         style="white", overflow="fold")
    table.add_column("Hosts",        justify="center")

    for t in techniques[:8]:
        table.add_row(t["id"], t["name"][:42], str(t["hosts"]))

    if not techniques:
        table.add_row("—", "No MITRE techniques mapped", "—")

    return Panel(table, title="[bold magenta]  MITRE ATT&CK Map[/bold magenta]", border_style="magenta")


def _make_device_panel(hosts: list) -> Panel:
    """Device type breakdown."""
    device_counts: dict = {}
    for h in hosts:
        dt = h.get("device_type", "Unknown")
        device_counts[dt] = device_counts.get(dt, 0) + 1

    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Device Type", style="white")
    table.add_column("Count",       style="cyan", justify="center")
    table.add_column("Bar",         style="green")

    max_count = max(device_counts.values()) if device_counts else 1
    for dtype, count in sorted(device_counts.items(), key=lambda x: -x[1]):
        bar_len = int(count / max_count * 15)
        table.add_row(dtype[:28], str(count), "█" * bar_len)

    return Panel(table, title="[bold] Device Map[/bold]", border_style="blue")


def _make_threat_panel(hosts: list) -> Panel:
    """Threat actor summary if available."""
    all_actors = []
    for h in hosts:
        for a in h.get("threat_actors", []):
            if a not in all_actors:
                all_actors.append(a)

    all_actors.sort(key=lambda x: x.get("match_score", 0), reverse=True)

    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Threat Actor",   style="bold red")
    table.add_column("Origin",         style="dim")
    table.add_column("Motivation",     style="yellow")
    table.add_column("Sophistication", justify="center")

    soph_icons = {1: "●○○○○", 2: "●●○○○", 3: "●●●○○", 4: "●●●●○", 5: "●●●●●"}
    for actor in all_actors[:5]:
        soph = soph_icons.get(actor.get("sophistication", 1), "●○○○○")
        table.add_row(
            actor.get("name", "?")[:20],
            actor.get("origin", "?")[:12],
            actor.get("motivation", "?")[:14],
            f"[red]{soph}[/red]" if actor.get("sophistication", 0) >= 4 else f"[yellow]{soph}[/yellow]",
        )

    if not all_actors:
        table.add_row("No threat actors matched", "—", "—", "—")

    return Panel(table, title="[bold red]  Threat Actor Profiler[/bold red]", border_style="red")


def _make_clock() -> Text:
    t = Text(justify="center")
    t.append(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"), style="bold dim")
    return t


def _build_layout(hosts: list, scan_time: str) -> Layout:
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=7),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    layout["body"].split_row(
        Layout(name="left",  ratio=3),
        Layout(name="right", ratio=2),
    )

    layout["left"].split_column(
        Layout(name="hosts",    ratio=3),
        Layout(name="cve_feed", ratio=2),
    )

    layout["right"].split_column(
        Layout(name="mitre",   ratio=2),
        Layout(name="devices", ratio=1),
        Layout(name="threats", ratio=2),
    )

    layout["header"].update(_make_header(hosts, scan_time))
    layout["hosts"].update(_make_host_table(hosts))
    layout["cve_feed"].update(_make_cve_feed(hosts))
    layout["mitre"].update(_make_mitre_panel(hosts))
    layout["devices"].update(_make_device_panel(hosts))
    layout["threats"].update(_make_threat_panel(hosts))
    layout["footer"].update(
        Panel(
            Align(_make_clock(), align="center"),
            border_style="dim",
            padding=(0, 0),
        )
    )

    return layout


def run_dashboard(
    hosts: list,
    scan_time: str = None,
    refresh_fn: Callable = None,
    refresh_interval: int = 30,
):
    """
    Launch the interactive live dashboard.

    Args:
        hosts: List of enriched host dicts.
        scan_time: When the scan was performed (defaults to now).
        refresh_fn: Optional callable that returns updated hosts list.
        refresh_interval: Seconds between refresh_fn calls (default 30).
    """
    if scan_time is None:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _hosts = list(hosts)
    _last_refresh = time.time()

    console.print()
    console.print(
        Panel(
            "[bold cyan]Launching Security Dashboard…[/bold cyan]\n"
            "[dim]Press [bold]Ctrl+C[/bold] to exit[/dim]",
            border_style="cyan",
        )
    )
    time.sleep(0.5)

    try:
        with Live(
            _build_layout(_hosts, scan_time),
            console=console,
            refresh_per_second=1,
            screen=True,
        ) as live:
            while True:
                time.sleep(1)

                # Auto-refresh if a refresh function is provided
                if refresh_fn and (time.time() - _last_refresh) >= refresh_interval:
                    try:
                        updated = refresh_fn()
                        if updated:
                            _hosts = updated
                            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                    _last_refresh = time.time()

                live.update(_build_layout(_hosts, scan_time))

    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard closed.[/dim]")
