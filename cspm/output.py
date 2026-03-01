from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cspm.models import ScanResult, Severity

if TYPE_CHECKING:
    from cspm.graph import ToxicCombination

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def print_results(
    result: ScanResult,
    no_color: bool = False,
    acked: list | None = None,
    show_acked: bool = False,
) -> None:
    console = Console(no_color=no_color)
    acked = acked or []

    # Header
    suppressed_line = f"\nSuppressed: {len(acked)}" if acked else ""
    console.print(Panel(
        f"[bold]AWS CSPM Scan Results[/bold]\n"
        f"Account: {result.account_id}  |  Time: {result.scan_time}\n"
        f"Total findings: {len(result.findings)}{suppressed_line}",
        title="cspm",
        border_style="bright_blue",
    ))

    # Summary by severity
    summary = Table(title="Summary by Severity", show_lines=False)
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.severity == sev)
        color = SEVERITY_COLORS[sev]
        summary.add_row(f"[{color}]{sev.value}[/{color}]", str(count))
    console.print(summary)
    console.print()

    if not result.findings:
        console.print("[bold green]No findings. Your account looks clean![/bold green]")
        return

    # Findings table
    table = Table(title="Findings", show_lines=True, expand=True)
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Service", width=12)
    table.add_column("Title", min_width=30)
    table.add_column("Resource", min_width=20)
    table.add_column("Region", width=14)

    for f in result.findings:
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            f.check_id,
            f"[{color}]{f.severity.value}[/{color}]",
            f.service,
            f.title,
            _truncate(f.resource_arn, 50),
            f.region,
        )
    console.print(table)

    # Vulnerability table (only when CVE findings exist)
    vuln_findings = [f for f in result.findings if f.cve_id is not None]
    if vuln_findings:
        console.print()
        vtable = Table(title="Container Vulnerabilities", show_lines=True, expand=True)
        vtable.add_column("CVE", style="bold", width=18)
        vtable.add_column("Severity", width=10)
        vtable.add_column("CVSS", justify="right", width=6)
        vtable.add_column("EPSS", justify="right", width=8)
        vtable.add_column("Exploit", width=8)
        vtable.add_column("Fix", width=6)
        vtable.add_column("Package", min_width=20)
        vtable.add_column("Resource", min_width=20)

        for f in vuln_findings:
            color = SEVERITY_COLORS[f.severity]
            cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
            epss_str = f"{f.epss_score:.2%}" if f.epss_score is not None else "-"

            if f.exploit_available is None:
                exploit_str = "-"
            elif f.exploit_available:
                exploit_str = "[bold red]YES[/bold red]"
            else:
                exploit_str = "NO"

            if f.fix_available is None:
                fix_str = "-"
            elif f.fix_available:
                fix_str = "[bold green]YES[/bold green]"
            else:
                fix_str = "NO"

            pkg_str = f.package_name or "-"
            if f.package_name and f.package_version:
                pkg_str = f"{f.package_name} {f.package_version}"
                if f.fixed_in_version:
                    pkg_str += f" \u2192 {f.fixed_in_version}"

            vtable.add_row(
                f.cve_id,
                f"[{color}]{f.severity.value}[/{color}]",
                cvss_str,
                epss_str,
                exploit_str,
                fix_str,
                pkg_str,
                _truncate(f.resource_arn, 40),
            )
        console.print(vtable)

    # Exposure path diagram (only when reachable CVE findings exist)
    _render_exposure_diagram(console, result.findings)

    # Detail section for recommendations — posture checks only, CVE noise suppressed
    console.print()
    console.print("[bold]Recommendations:[/bold]")
    seen: set[str] = set()
    for f in result.findings:
        if f.check_id in seen:
            continue
        seen.add(f.check_id)
        if f.cve_id is not None:
            continue  # CVE recommendations shown in exposure diagram
        color = SEVERITY_COLORS[f.severity]
        console.print(
            f"  [{color}]{f.check_id}[/{color}] {f.title}: {f.recommendation}"
        )

    # Acknowledged findings (shown only with --show-acked)
    if show_acked and acked:
        console.print()
        ack_table = Table(
            title=f"Acknowledged Findings ({len(acked)} suppressed)",
            show_lines=True,
            expand=True,
        )
        ack_table.add_column("ID", style="dim", width=8)
        ack_table.add_column("Severity", width=10)
        ack_table.add_column("Service", width=12)
        ack_table.add_column("Title", min_width=30)
        ack_table.add_column("Resource", min_width=20)
        ack_table.add_column("Region", width=14)
        for f in acked:
            color = SEVERITY_COLORS[f.severity]
            ack_table.add_row(
                f.check_id,
                f"[{color}]{f.severity.value}[/{color}]",
                f.service,
                f.title,
                _truncate(f.resource_arn, 50),
                f.region,
            )
        console.print(ack_table)


def _render_exposure_diagram(console: Console, findings: list) -> None:
    """Print an arrow diagram showing internet → LB/direct → resource → CVEs."""
    reachable = [
        f for f in findings
        if f.cve_id is not None and (f.via_lbs or f.direct_ports)
    ]
    if not reachable:
        return

    # Group by resource so we print each instance/task once
    by_resource: dict[str, dict] = {}
    for f in reachable:
        key = f.resource_arn
        if key not in by_resource:
            by_resource[key] = {
                "short": f.resource_arn.rsplit("/", 1)[-1],
                "via_lbs": list(f.via_lbs or []),
                "direct_ports": list(f.direct_ports or []),
                "cves": [],
            }
        # Merge exposure paths in case multiple CVEs on same resource differ
        for lb in f.via_lbs or []:
            if lb not in by_resource[key]["via_lbs"]:
                by_resource[key]["via_lbs"].append(lb)
        for p in f.direct_ports or []:
            if p not in by_resource[key]["direct_ports"]:
                by_resource[key]["direct_ports"].append(p)
        by_resource[key]["cves"].append(f)

    console.print()
    console.print("[bold]Internet Exposure Paths:[/bold]")
    console.print("  " + "─" * 72)

    for data in by_resource.values():
        short = data["short"]

        # Arrow line(s) — one per exposure vector
        for lb in data["via_lbs"]:
            console.print(f"  [bright_cyan]Internet[/bright_cyan] → [yellow]{lb}[/yellow] → [bold]{short}[/bold]")
        if data["direct_ports"]:
            ports = ", ".join(data["direct_ports"])
            console.print(f"  [bright_cyan]Internet[/bright_cyan] ([white]{ports}[/white]) → [bold]{short}[/bold]")

        # CVEs indented under the resource
        cves = sorted(data["cves"], key=lambda f: (f.severity.value, f.cve_id or ""))
        for i, f in enumerate(cves):
            prefix = "  └─" if i == len(cves) - 1 else "  ├─"
            color = SEVERITY_COLORS[f.severity]
            cvss = f"CVSS {f.cvss_score:.1f}" if f.cvss_score is not None else ""
            epss = f"EPSS {f.epss_score:.0%}" if f.epss_score is not None else ""
            exploit = (
                "[bold red]exploit YES[/bold red]" if f.exploit_available
                else "exploit NO" if f.exploit_available is not None
                else ""
            )
            pkg = ""
            if f.package_name:
                pkg = f.package_name
                if f.package_version:
                    pkg += f" {f.package_version}"
                if f.fixed_in_version:
                    pkg += f" → {f.fixed_in_version}"

            meta = "  ".join(part for part in [cvss, epss, exploit, pkg] if part)
            console.print(
                f"    {prefix} [{color}]{f.cve_id}[/{color}]"
                f"  [{color}]{f.severity.value}[/{color}]"
                f"  {meta}"
            )

        console.print()

    console.print("  " + "─" * 72)


def print_graph_results(
    combos: list[ToxicCombination],
    no_color: bool = False,
) -> None:
    console = Console(no_color=no_color)

    if not combos:
        console.print(Panel(
            "[bold green]No toxic combinations found.[/bold green]",
            title="Security Graph",
            border_style="bright_blue",
        ))
        return

    console.print(Panel(
        f"[bold]{len(combos)} toxic combination(s) found[/bold]",
        title="Security Graph",
        border_style="bright_blue",
    ))

    for combo in combos:
        color = SEVERITY_COLORS.get(combo.severity, "white")
        console.print()
        console.print(f"  [{color}][{combo.severity.value}][/{color}] {combo.title}")
        console.print()

        for i, step in enumerate(combo.path):
            if i == 0:
                console.print(f"    [bright_cyan]{step}[/bright_cyan]")
            elif i == len(combo.path) - 1:
                console.print(f"    └─ {step}")
            else:
                console.print(f"    ├─ {step}")

        console.print()
        console.print(f"  {combo.description}")
        console.print()
        console.print(f"  [bold]Fix:[/bold] {combo.recommendation}")
        console.print()
        console.print("  " + "─" * 72)


def export_json(result: ScanResult, path: str) -> None:
    with open(path, "w") as fh:
        fh.write(result.to_json())
    Console().print(f"\n[bold green]JSON report written to {path}[/bold green]")


def _truncate(s: str, length: int) -> str:
    return s if len(s) <= length else s[: length - 3] + "..."
