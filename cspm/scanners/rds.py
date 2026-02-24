from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner


@register_scanner
class RDSScanner(BaseScanner):
    service_name = "RDS"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        rds = self._get_client("rds")

        instances = self._get_all_instances(rds)
        for instance in instances:
            findings.extend(self._check_publicly_accessible(instance))
            findings.extend(self._check_storage_encrypted(instance))
            findings.extend(self._check_auto_minor_version_upgrade(instance))
            findings.extend(self._check_multi_az(instance))
            findings.extend(self._check_backup_retention(instance))
            findings.extend(self._check_deletion_protection(instance))

        snapshots = self._get_all_snapshots(rds)
        for snapshot in snapshots:
            findings.extend(self._check_snapshot_public(rds, snapshot))

        return findings

    def _get_all_instances(self, rds) -> list[dict]:
        instances = []
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances

    def _get_all_snapshots(self, rds) -> list[dict]:
        snapshots = []
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            snapshots.extend(page.get("DBSnapshots", []))
        return snapshots

    def _check_publicly_accessible(self, instance: dict) -> list[Finding]:
        if instance.get("PubliclyAccessible", False):
            return [Finding(
                check_id="RDS_001",
                service="RDS",
                severity=Severity.CRITICAL,
                title="RDS Instance Publicly Accessible",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"is publicly accessible."
                ),
                recommendation="Disable public accessibility and use private subnets with security groups to control access.",
            )]
        return []

    def _check_storage_encrypted(self, instance: dict) -> list[Finding]:
        if not instance.get("StorageEncrypted", False):
            return [Finding(
                check_id="RDS_002",
                service="RDS",
                severity=Severity.HIGH,
                title="RDS Instance Not Encrypted",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"does not have storage encryption enabled."
                ),
                recommendation="Enable encryption at rest. Note: enabling encryption requires creating an encrypted snapshot and restoring from it.",
            )]
        return []

    def _check_auto_minor_version_upgrade(self, instance: dict) -> list[Finding]:
        if not instance.get("AutoMinorVersionUpgrade", False):
            return [Finding(
                check_id="RDS_003",
                service="RDS",
                severity=Severity.LOW,
                title="RDS Instance Auto Minor Version Upgrade Disabled",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"does not have auto minor version upgrade enabled."
                ),
                recommendation="Enable auto minor version upgrade to receive security patches automatically.",
            )]
        return []

    def _check_multi_az(self, instance: dict) -> list[Finding]:
        if not instance.get("MultiAZ", False):
            return [Finding(
                check_id="RDS_004",
                service="RDS",
                severity=Severity.MEDIUM,
                title="RDS Instance Multi-AZ Disabled",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"is not configured for Multi-AZ deployment."
                ),
                recommendation="Enable Multi-AZ for high availability and automatic failover.",
            )]
        return []

    def _check_backup_retention(self, instance: dict) -> list[Finding]:
        retention = instance.get("BackupRetentionPeriod", 0)
        if retention < 7:
            return [Finding(
                check_id="RDS_005",
                service="RDS",
                severity=Severity.MEDIUM,
                title="RDS Instance Backup Retention Too Short",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"has a backup retention period of {retention} days, which is less than 7 days."
                ),
                recommendation="Set the backup retention period to at least 7 days.",
            )]
        return []

    def _check_snapshot_public(self, rds, snapshot: dict) -> list[Finding]:
        try:
            resp = rds.describe_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot["DBSnapshotIdentifier"],
                AttributeName="restore",
            )
            attr = resp.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
            for a in attr:
                if a.get("AttributeName") == "restore" and "all" in a.get("AttributeValues", []):
                    return [Finding(
                        check_id="RDS_006",
                        service="RDS",
                        severity=Severity.CRITICAL,
                        title="RDS Snapshot Is Public",
                        resource_arn=snapshot["DBSnapshotArn"],
                        region=self.region,
                        description=(
                            f"RDS snapshot '{snapshot['DBSnapshotIdentifier']}' "
                            f"is publicly accessible (shared with all AWS accounts)."
                        ),
                        recommendation="Remove public access from the snapshot by modifying the snapshot attribute to revoke the 'all' restore permission.",
                    )]
        except ClientError:
            pass
        return []

    def _check_deletion_protection(self, instance: dict) -> list[Finding]:
        if not instance.get("DeletionProtection", False):
            return [Finding(
                check_id="RDS_007",
                service="RDS",
                severity=Severity.MEDIUM,
                title="RDS Instance Deletion Protection Disabled",
                resource_arn=instance["DBInstanceArn"],
                region=self.region,
                description=(
                    f"RDS instance '{instance['DBInstanceIdentifier']}' "
                    f"does not have deletion protection enabled."
                ),
                recommendation="Enable deletion protection to prevent accidental deletion of the database instance.",
            )]
        return []
