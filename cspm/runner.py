import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import boto3

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

# Each worker thread gets its own boto3 session so we never share a session
# across threads (boto3 sessions are not thread-safe).
_thread_local = threading.local()


def _thread_session(original: boto3.Session) -> boto3.Session:
    """Return a boto3 session for the current thread, creating one if needed.

    We mirror the original session's credentials so all threads use the same
    AWS identity regardless of how the caller authenticated (profile, env
    vars, instance metadata, explicit keys).
    """
    if not hasattr(_thread_local, "session"):
        frozen = original.get_credentials().get_frozen_credentials()
        _thread_local.session = boto3.Session(
            aws_access_key_id=frozen.access_key,
            aws_secret_access_key=frozen.secret_key,
            aws_session_token=frozen.token,
            region_name=original.region_name,
        )
    return _thread_local.session


def run_scan(
    session: boto3.Session,
    regions: list[str],
    services: list[str] | None = None,
    min_severity: str | None = None,
    progress_callback=None,
    max_workers: int = 10,
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

    # Build flat task list — global services (IAM) run once regardless of regions
    tasks: list[tuple[str, type, str]] = []
    global_seen: set[str] = set()
    for region in regions:
        for name, scanner_cls in scanners_to_run.items():
            if name in GLOBAL_SERVICES:
                if name in global_seen:
                    continue
                global_seen.add(name)
            tasks.append((name, scanner_cls, region))

    if not tasks:
        return result

    findings_lock = threading.Lock()

    def _run(name: str, scanner_cls: type, region: str) -> list:
        if progress_callback:
            progress_callback(name, region)
        sess = _thread_session(session)
        scanner = scanner_cls(session=sess, region=region)
        return scanner.run()

    workers = min(max_workers, len(tasks))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_label = {
            executor.submit(_run, name, cls, region): f"{name}/{region}"
            for name, cls, region in tasks
        }
        for future in as_completed(future_to_label):
            label = future_to_label[future]
            try:
                findings = future.result()
                with findings_lock:
                    result.findings.extend(findings)
            except Exception as e:
                print(f"  [WARNING] Scanner {label} failed: {e}")

    # Filter by minimum severity
    if min_severity:
        threshold = SEVERITY_ORDER[Severity(min_severity)]
        result.findings = [
            f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold
        ]

    # Sort: CRITICAL first
    result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

    return result
