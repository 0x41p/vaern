from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner


@register_scanner
class S3Scanner(BaseScanner):
    service_name = "S3"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        s3 = self._get_client("s3")
        s3control = self._get_client("s3control")

        # Account-level public access block check
        findings.extend(self._check_account_public_access_block(s3control))

        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            region = self._get_bucket_region(s3, name)
            # Use a region-specific client for per-bucket calls
            regional_s3 = self.session.client("s3", region_name=region)

            findings.extend(self._check_bucket_public_access_block(regional_s3, name, region))
            findings.extend(self._check_encryption(regional_s3, name, region))
            findings.extend(self._check_versioning(regional_s3, name, region))
            findings.extend(self._check_logging(regional_s3, name, region))
            findings.extend(self._check_policy_public(regional_s3, name, region))

        return findings

    def _get_bucket_region(self, s3, bucket_name: str) -> str:
        try:
            resp = s3.get_bucket_location(Bucket=bucket_name)
            location = resp.get("LocationConstraint")
            # None means us-east-1
            return location or "us-east-1"
        except ClientError:
            return "us-east-1"

    def _check_account_public_access_block(self, s3control) -> list[Finding]:
        try:
            sts = self.session.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            resp = s3control.get_public_access_block(AccountId=account_id)
            config = resp["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                return [Finding(
                    check_id="S3_001",
                    service="S3",
                    severity=Severity.CRITICAL,
                    title="S3 Account-Level Public Access Block Not Fully Enabled",
                    resource_arn=f"arn:aws:s3:::{account_id}",
                    region="global",
                    description="The S3 account-level public access block does not have all four settings enabled.",
                    recommendation="Enable all four public access block settings at the account level.",
                )]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                sts = self.session.client("sts")
                account_id = sts.get_caller_identity()["Account"]
                return [Finding(
                    check_id="S3_001",
                    service="S3",
                    severity=Severity.CRITICAL,
                    title="S3 Account-Level Public Access Block Not Configured",
                    resource_arn=f"arn:aws:s3:::{account_id}",
                    region="global",
                    description="No S3 account-level public access block configuration exists.",
                    recommendation="Enable all four public access block settings at the account level.",
                )]
        return []

    def _check_bucket_public_access_block(self, s3, bucket_name: str, region: str) -> list[Finding]:
        try:
            resp = s3.get_public_access_block(Bucket=bucket_name)
            config = resp["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                return [Finding(
                    check_id="S3_002",
                    service="S3",
                    severity=Severity.CRITICAL,
                    title="S3 Bucket Public Access Not Fully Blocked",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    description=f"Bucket '{bucket_name}' does not have all four public access block settings enabled.",
                    recommendation="Enable all four public access block settings on this bucket.",
                )]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return [Finding(
                    check_id="S3_002",
                    service="S3",
                    severity=Severity.CRITICAL,
                    title="S3 Bucket Public Access Block Not Configured",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    description=f"Bucket '{bucket_name}' has no public access block configuration.",
                    recommendation="Enable all four public access block settings on this bucket.",
                )]
        return []

    def _check_encryption(self, s3, bucket_name: str, region: str) -> list[Finding]:
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return [Finding(
                    check_id="S3_003",
                    service="S3",
                    severity=Severity.HIGH,
                    title="S3 Bucket Server-Side Encryption Disabled",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    description=f"Bucket '{bucket_name}' does not have server-side encryption enabled.",
                    recommendation="Enable default server-side encryption (SSE-S3 or SSE-KMS).",
                )]
        return []

    def _check_versioning(self, s3, bucket_name: str, region: str) -> list[Finding]:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        if resp.get("Status") != "Enabled":
            return [Finding(
                check_id="S3_004",
                service="S3",
                severity=Severity.MEDIUM,
                title="S3 Bucket Versioning Disabled",
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                region=region,
                description=f"Bucket '{bucket_name}' does not have versioning enabled.",
                recommendation="Enable versioning to protect against accidental deletion or overwriting.",
            )]
        return []

    def _check_logging(self, s3, bucket_name: str, region: str) -> list[Finding]:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in resp:
            return [Finding(
                check_id="S3_005",
                service="S3",
                severity=Severity.LOW,
                title="S3 Bucket Logging Disabled",
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                region=region,
                description=f"Bucket '{bucket_name}' does not have server access logging enabled.",
                recommendation="Enable server access logging to track requests to this bucket.",
            )]
        return []

    def _check_policy_public(self, s3, bucket_name: str, region: str) -> list[Finding]:
        try:
            resp = s3.get_bucket_policy_status(Bucket=bucket_name)
            if resp["PolicyStatus"]["IsPublic"]:
                return [Finding(
                    check_id="S3_006",
                    service="S3",
                    severity=Severity.CRITICAL,
                    title="S3 Bucket Policy Allows Public Access",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    description=f"Bucket '{bucket_name}' has a bucket policy that allows public access.",
                    recommendation="Review and restrict the bucket policy to remove public access.",
                )]
        except ClientError:
            # No policy exists — not a finding
            pass
        return []
