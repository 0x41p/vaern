from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner


@register_scanner
class EBSScanner(BaseScanner):
    service_name = "EBS"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = self._get_client("ec2")
        account_id = self.session.client("sts").get_caller_identity()["Account"]

        findings.extend(self._check_default_encryption(ec2, account_id))
        findings.extend(self._check_volumes(ec2, account_id))
        findings.extend(self._check_public_snapshots(ec2, account_id))

        return findings

    def _check_default_encryption(self, ec2, account_id: str) -> list[Finding]:
        """EBS_001 - Check if EBS default encryption is enabled for the region."""
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", False):
            return [Finding(
                check_id="EBS_001",
                service="EBS",
                severity=Severity.HIGH,
                title="EBS Default Encryption Not Enabled",
                resource_arn=f"arn:aws:ec2:{self.region}:{account_id}:account",
                region=self.region,
                description=(
                    f"EBS default encryption is not enabled in region {self.region}. "
                    "New volumes created in this region will not be automatically encrypted."
                ),
                recommendation="Enable EBS default encryption for this region to ensure all new volumes are encrypted at rest.",
            )]
        return []

    def _check_volumes(self, ec2, account_id: str) -> list[Finding]:
        """EBS_002 and EBS_003 - Check volume encryption and attachment status."""
        findings: list[Finding] = []
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                vol_id = volume["VolumeId"]
                vol_arn = f"arn:aws:ec2:{self.region}:{account_id}:volume/{vol_id}"

                # EBS_002 - Volume not encrypted
                if not volume.get("Encrypted", False):
                    findings.append(Finding(
                        check_id="EBS_002",
                        service="EBS",
                        severity=Severity.HIGH,
                        title="EBS Volume Not Encrypted",
                        resource_arn=vol_arn,
                        region=self.region,
                        description=f"EBS volume '{vol_id}' is not encrypted at rest.",
                        recommendation="Encrypt the volume by creating an encrypted snapshot and restoring from it, or enable EBS default encryption.",
                    ))

                # EBS_003 - Orphaned volume (not attached to any instance)
                if not volume.get("Attachments"):
                    findings.append(Finding(
                        check_id="EBS_003",
                        service="EBS",
                        severity=Severity.LOW,
                        title="EBS Volume Not Attached to Any Instance",
                        resource_arn=vol_arn,
                        region=self.region,
                        description=f"EBS volume '{vol_id}' is not attached to any EC2 instance (orphaned volume).",
                        recommendation="Review and delete unused volumes to reduce costs and minimize the attack surface.",
                    ))

        return findings

    def _check_public_snapshots(self, ec2, account_id: str) -> list[Finding]:
        """EBS_004 - Check if any EBS snapshots are publicly shared."""
        findings: list[Finding] = []
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snapshot in page.get("Snapshots", []):
                snap_id = snapshot["SnapshotId"]
                snap_arn = f"arn:aws:ec2:{self.region}:{account_id}:snapshot/{snap_id}"

                try:
                    attr_resp = ec2.describe_snapshot_attribute(
                        SnapshotId=snap_id,
                        Attribute="createVolumePermission",
                    )
                    permissions = attr_resp.get("CreateVolumePermissions", [])
                    if {"Group": "all"} in permissions:
                        findings.append(Finding(
                            check_id="EBS_004",
                            service="EBS",
                            severity=Severity.CRITICAL,
                            title="EBS Snapshot Is Public",
                            resource_arn=snap_arn,
                            region=self.region,
                            description=f"EBS snapshot '{snap_id}' is publicly shared, allowing any AWS account to create volumes from it.",
                            recommendation="Remove the public 'createVolumePermission' from this snapshot to restrict access.",
                        ))
                except ClientError:
                    # If we cannot describe the snapshot attribute, skip it
                    pass

        return findings
