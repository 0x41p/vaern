import argparse
import sys
from datetime import datetime, timezone

import boto3
from rich.console import Console
from rich.table import Table

from cspm.runner import run_scan
from cspm.output import print_results, export_json
from cspm.acks import load_acks, save_acks, filter_findings, Ack, DEFAULT_ACK_FILE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cspm",
        description="Lightweight AWS Cloud Security Posture Management scanner",
    )
    parser.add_argument(
        "--services",
        nargs="+",
        default=None,
        help="Specific services to scan (e.g. S3 IAM EC2 RDS CloudTrail EBS Lambda ECS ECR ECSFargate). Default: all.",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=None,
        help="AWS regions to scan. Default: current region only.",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name to use.",
    )
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        default=None,
        help="Export findings to a JSON file.",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only show findings at this severity level or above.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        metavar="N",
        help="Max concurrent scanner threads (default: 10).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output.",
    )
    parser.add_argument(
        "--ack-file",
        metavar="FILE",
        default=DEFAULT_ACK_FILE,
        help=f"Path to acknowledgments file (default: {DEFAULT_ACK_FILE}).",
    )
    parser.add_argument(
        "--show-acked",
        action="store_true",
        help="Also display acknowledged (suppressed) findings at the end.",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    ack_parser = subparsers.add_parser("ack", help="Manage finding acknowledgments")
    ack_sub = ack_parser.add_subparsers(dest="ack_action", required=True)

    # ack add
    add_p = ack_sub.add_parser("add", help="Suppress a finding")
    add_p.add_argument(
        "--check-id", required=True, metavar="ID",
        help="Check ID to suppress, or '*' for all checks.",
    )
    add_p.add_argument(
        "--resource-arn", required=True, metavar="ARN",
        help="Resource ARN to suppress, or '*' for all resources.",
    )
    add_p.add_argument("--reason", required=True, help="Why this finding is being suppressed.")
    add_p.add_argument("--expires", metavar="DATE", default=None,
                       help="Optional expiry date in ISO-8601 format (e.g. 2027-01-01).")
    add_p.add_argument("--by", metavar="NAME", default="",
                       help="Your name or team (recorded for audit trail).")
    add_p.add_argument("--ack-file", metavar="FILE", default=DEFAULT_ACK_FILE,
                       help=f"Path to acknowledgments file (default: {DEFAULT_ACK_FILE}).")

    # ack list
    list_p = ack_sub.add_parser("list", help="List all acknowledgments")
    list_p.add_argument("--ack-file", metavar="FILE", default=DEFAULT_ACK_FILE,
                        help=f"Path to acknowledgments file (default: {DEFAULT_ACK_FILE}).")

    # ack remove
    remove_p = ack_sub.add_parser("remove", help="Remove an acknowledgment")
    remove_p.add_argument("--check-id", required=True, metavar="ID")
    remove_p.add_argument("--resource-arn", required=True, metavar="ARN")
    remove_p.add_argument("--ack-file", metavar="FILE", default=DEFAULT_ACK_FILE,
                          help=f"Path to acknowledgments file (default: {DEFAULT_ACK_FILE}).")

    return parser


def _handle_ack(args) -> None:
    console = Console()

    if args.ack_action == "add":
        acks = load_acks(args.ack_file)
        for existing in acks:
            if existing.check_id == args.check_id and existing.resource_arn == args.resource_arn:
                console.print(
                    f"[yellow]Acknowledgment already exists for {args.check_id} / {args.resource_arn}. "
                    f"Remove it first if you want to update it.[/yellow]"
                )
                return
        new_ack = Ack(
            check_id=args.check_id,
            resource_arn=args.resource_arn,
            reason=args.reason,
            acknowledged_by=args.by,
            acknowledged_at=datetime.now(timezone.utc).date().isoformat(),
            expires=args.expires,
        )
        acks.append(new_ack)
        save_acks(acks, args.ack_file)
        console.print(f"[bold green]Acknowledgment added to {args.ack_file}[/bold green]")
        console.print(f"  Check:    {new_ack.check_id}")
        console.print(f"  Resource: {new_ack.resource_arn}")
        console.print(f"  Reason:   {new_ack.reason}")
        if new_ack.expires:
            console.print(f"  Expires:  {new_ack.expires}")

    elif args.ack_action == "list":
        acks = load_acks(args.ack_file)
        if not acks:
            console.print(f"No acknowledgments in [bold]{args.ack_file}[/bold]")
            return
        table = Table(title=f"Acknowledgments ({args.ack_file})", show_lines=True)
        table.add_column("Check ID", style="bold")
        table.add_column("Resource ARN")
        table.add_column("Reason")
        table.add_column("By")
        table.add_column("Date")
        table.add_column("Expires")
        for a in acks:
            table.add_row(
                a.check_id,
                a.resource_arn,
                a.reason,
                a.acknowledged_by or "-",
                a.acknowledged_at or "-",
                a.expires or "never",
            )
        console.print(table)

    elif args.ack_action == "remove":
        acks = load_acks(args.ack_file)
        before = len(acks)
        acks = [
            a for a in acks
            if not (a.check_id == args.check_id and a.resource_arn == args.resource_arn)
        ]
        if len(acks) == before:
            console.print("[yellow]No matching acknowledgment found.[/yellow]")
        else:
            save_acks(acks, args.ack_file)
            console.print(f"[bold green]Removed {before - len(acks)} acknowledgment(s).[/bold green]")


def main():
    parser = build_parser()
    args = parser.parse_args()
    console = Console()

    if args.command == "ack":
        _handle_ack(args)
        return

    # --- Scan ---
    try:
        session = boto3.Session(profile_name=args.profile)
    except Exception as e:
        console.print(f"[bold red]Failed to create AWS session: {e}[/bold red]")
        sys.exit(1)

    if args.regions:
        regions = args.regions
    else:
        region = session.region_name or "us-east-1"
        regions = [region]

    console.print(f"[bold bright_blue]AWS CSPM Scanner[/bold bright_blue]")
    console.print(f"Scanning regions: {', '.join(regions)}")
    if args.services:
        console.print(f"Services: {', '.join(args.services)}")
    else:
        console.print("Services: all")
    console.print()

    def progress(service: str, region: str):
        console.print(f"  Scanning [bold]{service}[/bold] in {region}...")

    try:
        result = run_scan(
            session=session,
            regions=regions,
            services=args.services,
            min_severity=args.severity,
            progress_callback=progress,
            max_workers=args.workers,
        )
    except Exception as e:
        console.print(f"\n[bold red]Scan failed: {e}[/bold red]")
        sys.exit(1)

    # Apply acknowledgments
    acks = []
    try:
        acks = load_acks(args.ack_file)
    except ValueError as e:
        console.print(f"[yellow]Warning: {e}[/yellow]")

    active, acked = filter_findings(result.findings, acks)
    result.findings = active

    console.print()
    print_results(result, no_color=args.no_color, acked=acked, show_acked=args.show_acked)

    if args.output_json:
        export_json(result, args.output_json)


if __name__ == "__main__":
    main()
