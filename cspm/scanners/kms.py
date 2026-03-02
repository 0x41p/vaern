import json
import logging

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class KMSScanner(BaseScanner):
    service_name = "KMS"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        kms = self._get_client("kms")

        key_ids: list[str] = []
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            key_ids.extend(k["KeyId"] for k in page.get("Keys", []))

        for key_id in key_ids:
            try:
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
            except ClientError as e:
                logger.warning("KMS describe_key failed for %s: %s", key_id, e)
                continue

            # Only audit enabled customer-managed keys
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") != "Enabled":
                continue
            # Replica keys inherit rotation from their primary — skip them
            if (
                meta.get("MultiRegion")
                and meta.get("MultiRegionConfiguration", {}).get("MultiRegionKeyType")
                == "REPLICA"
            ):
                continue

            key_arn = meta.get("Arn", key_id)
            findings.extend(self._check_key_rotation(kms, key_id, key_arn))
            findings.extend(self._check_key_policy_public(kms, key_id, key_arn))

        return findings

    def _check_key_rotation(self, kms, key_id: str, key_arn: str) -> list[Finding]:
        """KMS_001 - Customer-Managed Key Rotation Disabled."""
        try:
            resp = kms.get_key_rotation_status(KeyId=key_id)
            if not resp.get("KeyRotationEnabled", False):
                return [Finding(
                    check_id="KMS_001",
                    service="KMS",
                    severity=Severity.MEDIUM,
                    title="KMS Customer-Managed Key Rotation Disabled",
                    resource_arn=key_arn,
                    region=self.region,
                    description=(
                        f"KMS key {key_arn} does not have automatic annual key rotation enabled. "
                        f"If the key material is ever exfiltrated, all data encrypted under it "
                        f"remains at risk indefinitely until the key is manually rotated."
                    ),
                    recommendation=(
                        "Enable automatic key rotation. AWS re-encrypts the backing key material annually "
                        "while keeping the same key ID and ARN — no application changes required."
                    ),
                )]
        except ClientError as e:
            # Asymmetric and HMAC keys do not support rotation — not a finding
            if e.response["Error"]["Code"] != "UnsupportedOperationException":
                logger.warning("get_key_rotation_status failed for %s: %s", key_id, e)
        return []

    def _check_key_policy_public(self, kms, key_id: str, key_arn: str) -> list[Finding]:
        """KMS_002 - KMS Key Policy Allows Public Access."""
        try:
            resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
            policy = json.loads(resp.get("Policy", "{}"))
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                if "Condition" in stmt:
                    continue
                principal = stmt.get("Principal", {})
                is_public = principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                )
                if is_public:
                    return [Finding(
                        check_id="KMS_002",
                        service="KMS",
                        severity=Severity.CRITICAL,
                        title="KMS Key Policy Allows Public Access",
                        resource_arn=key_arn,
                        region=self.region,
                        description=(
                            f"KMS key {key_arn} has a key policy granting access to all principals "
                            f"(Principal: \"*\") without any conditions. "
                            f"Any authenticated AWS entity, including from other accounts, "
                            f"can use this key to encrypt or decrypt data."
                        ),
                        recommendation=(
                            "Restrict the key policy Principal to specific IAM principals, roles, "
                            "or accounts that require access. "
                            "Remove all Principal: \"*\" Allow statements."
                        ),
                    )]
        except ClientError as e:
            logger.warning("get_key_policy failed for %s: %s", key_id, e)
        return []
