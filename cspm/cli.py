import argparse
import sys

import boto3
from rich.console import Console

from cspm.runner import run_scan
from cspm.output import print_results, export_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cspm",
        description="Lightweight AWS Cloud Security Posture Management scanner",
    )
    parser.add_argument(
        "--services",
        nargs="+",
        default=None,
        help="Specific services to scan (e.g. S3 IAM EC2 RDS CloudTrail EBS Lambda). Default: all.",
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
        "--no-color",
        action="store_true",
        help="Disable colored output.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    console = Console()

    # Create boto3 session
    try:
        session = boto3.Session(profile_name=args.profile)
    except Exception as e:
        console.print(f"[bold red]Failed to create AWS session: {e}[/bold red]")
        sys.exit(1)

    # Determine regions
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
        )
    except Exception as e:
        console.print(f"\n[bold red]Scan failed: {e}[/bold red]")
        sys.exit(1)

    console.print()
    print_results(result, no_color=args.no_color)

    if args.output_json:
        export_json(result, args.output_json)


if __name__ == "__main__":
    main()
