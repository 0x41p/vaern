from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner


@register_scanner
class CloudTrailScanner(BaseScanner):
    service_name = "CloudTrail"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        ct = self._get_client("cloudtrail")

        trails = ct.describe_trails().get("trailList", [])

        findings.extend(self._check_ct001_not_enabled(ct, trails))

        for trail in trails:
            trail_arn = trail["TrailARN"]
            findings.extend(self._check_ct002_log_file_validation(trail, trail_arn))
            findings.extend(self._check_ct003_kms_encryption(trail, trail_arn))
            findings.extend(self._check_ct004_s3_access_logging(trail, trail_arn))
            findings.extend(self._check_ct005_cloudwatch_integration(trail, trail_arn))

        return findings

    def _check_ct001_not_enabled(self, ct, trails: list[dict]) -> list[Finding]:
        """CT_001 - CloudTrail Not Enabled.

        Checks that at least one multi-region trail exists and is actively
        logging.  Produces a finding if no multi-region trail is found, or if
        every multi-region trail has IsLogging set to False.
        """
        multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail", False)]

        if not multi_region_trails:
            # No multi-region trail exists at all
            return [Finding(
                check_id="CT_001",
                service="CloudTrail",
                severity=Severity.CRITICAL,
                title="CloudTrail Not Enabled",
                resource_arn=f"arn:aws:cloudtrail:{self.region}",
                region=self.region,
                description="No multi-region CloudTrail trail is configured in this account.",
                recommendation=(
                    "Create a multi-region CloudTrail trail to ensure all API activity "
                    "is logged across every AWS region."
                ),
            )]

        # Check if at least one multi-region trail is actively logging
        findings: list[Finding] = []
        any_logging = False
        for trail in multi_region_trails:
            trail_arn = trail["TrailARN"]
            try:
                status = ct.get_trail_status(Name=trail_arn)
                if status.get("IsLogging", False):
                    any_logging = True
                    break
            except ClientError:
                pass

        if not any_logging:
            # Use the first multi-region trail ARN for the finding
            findings.append(Finding(
                check_id="CT_001",
                service="CloudTrail",
                severity=Severity.CRITICAL,
                title="CloudTrail Not Enabled",
                resource_arn=multi_region_trails[0]["TrailARN"],
                region=self.region,
                description=(
                    "A multi-region CloudTrail trail exists but is not currently logging. "
                    "API activity is not being recorded."
                ),
                recommendation="Enable logging on the multi-region CloudTrail trail.",
            ))

        return findings

    def _check_ct002_log_file_validation(self, trail: dict, trail_arn: str) -> list[Finding]:
        """CT_002 - CloudTrail Log File Validation Disabled."""
        if not trail.get("LogFileValidationEnabled", False):
            return [Finding(
                check_id="CT_002",
                service="CloudTrail",
                severity=Severity.HIGH,
                title="CloudTrail Log File Validation Disabled",
                resource_arn=trail_arn,
                region=self.region,
                description=(
                    f"Trail '{trail.get('Name', trail_arn)}' does not have log file "
                    "validation enabled. Without validation, it is not possible to "
                    "determine whether log files have been tampered with."
                ),
                recommendation=(
                    "Enable log file validation on this trail to ensure the integrity "
                    "and authenticity of CloudTrail log files."
                ),
            )]
        return []

    def _check_ct003_kms_encryption(self, trail: dict, trail_arn: str) -> list[Finding]:
        """CT_003 - CloudTrail Logs Not Encrypted with KMS."""
        if not trail.get("KmsKeyId"):
            return [Finding(
                check_id="CT_003",
                service="CloudTrail",
                severity=Severity.HIGH,
                title="CloudTrail Logs Not Encrypted with KMS",
                resource_arn=trail_arn,
                region=self.region,
                description=(
                    f"Trail '{trail.get('Name', trail_arn)}' is not configured to encrypt "
                    "log files using a KMS customer-managed key. Logs are only protected "
                    "by default S3 server-side encryption."
                ),
                recommendation=(
                    "Configure a KMS CMK for CloudTrail log encryption to add an "
                    "additional layer of protection for sensitive audit data."
                ),
            )]
        return []

    def _check_ct004_s3_access_logging(self, trail: dict, trail_arn: str) -> list[Finding]:
        """CT_004 - CloudTrail S3 Bucket Access Logging Disabled."""
        bucket_name = trail.get("S3BucketName")
        if not bucket_name:
            return []

        s3 = self._get_client("s3")
        try:
            resp = s3.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in resp:
                return [Finding(
                    check_id="CT_004",
                    service="CloudTrail",
                    severity=Severity.MEDIUM,
                    title="CloudTrail S3 Bucket Access Logging Disabled",
                    resource_arn=trail_arn,
                    region=self.region,
                    description=(
                        f"The S3 bucket '{bucket_name}' used by trail "
                        f"'{trail.get('Name', trail_arn)}' does not have server access "
                        "logging enabled. Access to CloudTrail logs is not being tracked."
                    ),
                    recommendation=(
                        "Enable S3 server access logging on the CloudTrail destination "
                        "bucket to monitor who accesses the audit logs."
                    ),
                )]
        except ClientError:
            # If we cannot check the bucket (permissions, bucket in another
            # account, etc.), skip silently rather than producing a false
            # positive.
            pass

        return []

    def _check_ct005_cloudwatch_integration(self, trail: dict, trail_arn: str) -> list[Finding]:
        """CT_005 - CloudTrail Not Integrated with CloudWatch Logs."""
        if not trail.get("CloudWatchLogsLogGroupArn"):
            return [Finding(
                check_id="CT_005",
                service="CloudTrail",
                severity=Severity.MEDIUM,
                title="CloudTrail Not Integrated with CloudWatch Logs",
                resource_arn=trail_arn,
                region=self.region,
                description=(
                    f"Trail '{trail.get('Name', trail_arn)}' is not configured to send "
                    "logs to CloudWatch Logs. Real-time monitoring and alerting on API "
                    "activity is not available."
                ),
                recommendation=(
                    "Configure a CloudWatch Logs log group for this trail to enable "
                    "real-time monitoring, metric filters, and alarms on API activity."
                ),
            )]
        return []
