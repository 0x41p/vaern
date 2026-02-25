import boto3
from datetime import datetime, timezone

from cspm.models import ScanResult, Severity, SEVERITY_ORDER
from cspm.scanners import SCANNER_REGISTRY

# Force-import all scanner modules so @register_scanner decorators execute
import cspm.scanners.s3  # noqa: F401
import cspm.scanners.iam  # noqa: F401
import cspm.scanners.ec2  # noqa: F401
import cspm.scanners.rds  # noqa: F401
import cspm.scanners.cloudtrail  # noqa: F401
import cspm.scanners.ebs  # noqa: F401
import cspm.scanners.lambda_  # noqa: F401
import cspm.scanners.ecs  # noqa: F401
import cspm.scanners.ecr  # noqa: F401
import cspm.scanners.ecs_fargate  # noqa: F401

GLOBAL_SERVICES = {"IAM"}


def run_scan(
    session: boto3.Session,
    regions: list[str],
    services: list[str] | None = None,
    min_severity: str | None = None,
    progress_callback=None,
) -> ScanResult:
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    result = ScanResult(
        account_id=account_id,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    scanners_to_run = SCANNER_REGISTRY
    if services:
        upper = {s.upper() for s in services}
        scanners_to_run = {
            k: v for k, v in SCANNER_REGISTRY.items() if k.upper() in upper
        }

    global_done: set[str] = set()
    for region in regions:
        for name, scanner_cls in scanners_to_run.items():
            if name in GLOBAL_SERVICES:
                if name in global_done:
                    continue
                global_done.add(name)

            if progress_callback:
                progress_callback(name, region)

            scanner = scanner_cls(session=session, region=region)
            try:
                findings = scanner.run()
                result.findings.extend(findings)
            except Exception as e:
                print(f"  [WARNING] Scanner {name} failed in {region}: {e}")

    # Filter by minimum severity
    if min_severity:
        threshold = SEVERITY_ORDER[Severity(min_severity)]
        result.findings = [
            f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold
        ]

    # Sort: CRITICAL first
    result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

    return result
