from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cspm.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def print_results(result: ScanResult, no_color: bool = False) -> None:
    console = Console(no_color=no_color)

    # Header
    console.print(Panel(
        f"[bold]AWS CSPM Scan Results[/bold]\n"
        f"Account: {result.account_id}  |  Time: {result.scan_time}\n"
        f"Total findings: {len(result.findings)}",
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

    # Detail section for recommendations
    console.print()
    console.print("[bold]Recommendations:[/bold]")
    seen = set()
    for f in result.findings:
        if f.check_id not in seen:
            seen.add(f.check_id)
            color = SEVERITY_COLORS[f.severity]
            console.print(
                f"  [{color}]{f.check_id}[/{color}] {f.title}: {f.recommendation}"
            )


def export_json(result: ScanResult, path: str) -> None:
    with open(path, "w") as fh:
        fh.write(result.to_json())
    Console().print(f"\n[bold green]JSON report written to {path}[/bold green]")


def _truncate(s: str, length: int) -> str:
    return s if len(s) <= length else s[: length - 3] + "..."
