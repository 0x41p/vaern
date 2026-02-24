import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

STALE_DAYS = 90


@register_scanner
class IAMScanner(BaseScanner):
    service_name = "IAM"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        iam = self._get_client("iam")

        cred_report = self._get_credential_report(iam)

        findings.extend(self._check_root_mfa(cred_report))
        findings.extend(self._check_root_access_keys(cred_report))
        findings.extend(self._check_password_policy(iam))
        findings.extend(self._check_user_mfa(iam))
        findings.extend(self._check_direct_policies(iam))
        findings.extend(self._check_unused_access_keys(cred_report))
        findings.extend(self._check_password_rotation(cred_report))

        return findings

    def _get_credential_report(self, iam) -> list[dict]:
        # Generate the report — may need to poll
        for _ in range(10):
            try:
                resp = iam.generate_credential_report()
                if resp["State"] == "COMPLETE":
                    break
            except ClientError:
                pass
            time.sleep(2)

        resp = iam.get_credential_report()
        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    def _find_root(self, cred_report: list[dict]) -> dict | None:
        for row in cred_report:
            if row["user"] == "<root_account>":
                return row
        return None

    def _check_root_mfa(self, cred_report: list[dict]) -> list[Finding]:
        root = self._find_root(cred_report)
        if root and root.get("mfa_active", "false").lower() != "true":
            return [Finding(
                check_id="IAM_001",
                service="IAM",
                severity=Severity.CRITICAL,
                title="Root Account MFA Not Enabled",
                resource_arn="arn:aws:iam::root",
                region="global",
                description="The root account does not have MFA enabled.",
                recommendation="Enable MFA on the root account immediately using a hardware or virtual MFA device.",
            )]
        return []

    def _check_root_access_keys(self, cred_report: list[dict]) -> list[Finding]:
        root = self._find_root(cred_report)
        if not root:
            return []
        findings = []
        for key_num in ["1", "2"]:
            if root.get(f"access_key_{key_num}_active", "false").lower() == "true":
                findings.append(Finding(
                    check_id="IAM_002",
                    service="IAM",
                    severity=Severity.CRITICAL,
                    title=f"Root Account Access Key {key_num} Is Active",
                    resource_arn="arn:aws:iam::root",
                    region="global",
                    description=f"The root account has active access key {key_num}.",
                    recommendation="Delete root account access keys. Use IAM users or roles instead.",
                ))
        return findings

    def _check_password_policy(self, iam) -> list[Finding]:
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("minimum length < 14")
            for flag in ["RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"]:
                if not policy.get(flag, False):
                    issues.append(f"{flag} not enabled")
            if issues:
                return [Finding(
                    check_id="IAM_003",
                    service="IAM",
                    severity=Severity.HIGH,
                    title="IAM Password Policy Is Weak",
                    resource_arn="arn:aws:iam::password-policy",
                    region="global",
                    description=f"Password policy issues: {', '.join(issues)}.",
                    recommendation="Set minimum password length to 14+, require symbols, numbers, upper and lowercase.",
                )]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return [Finding(
                    check_id="IAM_003",
                    service="IAM",
                    severity=Severity.HIGH,
                    title="IAM Password Policy Not Configured",
                    resource_arn="arn:aws:iam::password-policy",
                    region="global",
                    description="No custom password policy is configured for this account.",
                    recommendation="Configure a strong password policy with minimum 14 characters and complexity requirements.",
                )]
        return []

    def _check_user_mfa(self, iam) -> list[Finding]:
        findings = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                arn = user["Arn"]
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa_devices:
                    # Only flag users that have console access (password enabled)
                    try:
                        iam.get_login_profile(UserName=username)
                        findings.append(Finding(
                            check_id="IAM_004",
                            service="IAM",
                            severity=Severity.HIGH,
                            title="IAM User MFA Not Enabled",
                            resource_arn=arn,
                            region="global",
                            description=f"IAM user '{username}' has console access but no MFA device configured.",
                            recommendation="Enable MFA for this user.",
                        ))
                    except ClientError:
                        # No login profile — programmatic-only user, skip
                        pass
        return findings

    def _check_direct_policies(self, iam) -> list[Finding]:
        findings = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                arn = user["Arn"]
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                if attached or inline:
                    findings.append(Finding(
                        check_id="IAM_005",
                        service="IAM",
                        severity=Severity.MEDIUM,
                        title="IAM User Has Directly Attached Policies",
                        resource_arn=arn,
                        region="global",
                        description=f"IAM user '{username}' has {len(attached)} managed and {len(inline)} inline policies attached directly.",
                        recommendation="Attach policies to groups or roles instead of directly to users.",
                    ))
        return findings

    def _check_unused_access_keys(self, cred_report: list[dict]) -> list[Finding]:
        findings = []
        now = datetime.now(timezone.utc)
        for row in cred_report:
            if row["user"] == "<root_account>":
                continue
            for key_num in ["1", "2"]:
                if row.get(f"access_key_{key_num}_active", "false").lower() != "true":
                    continue
                last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                if last_used == "N/A" or last_used == "no_information":
                    # Key exists but never used — flag it
                    findings.append(Finding(
                        check_id="IAM_006",
                        service="IAM",
                        severity=Severity.MEDIUM,
                        title=f"Unused IAM Access Key {key_num}",
                        resource_arn=row.get("arn", "unknown"),
                        region="global",
                        description=f"User '{row['user']}' has active access key {key_num} that has never been used.",
                        recommendation="Remove unused access keys.",
                    ))
                    continue
                try:
                    last_dt = datetime.fromisoformat(last_used.replace("+00:00", "+00:00"))
                    if not last_dt.tzinfo:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    age_days = (now - last_dt).days
                    if age_days > STALE_DAYS:
                        findings.append(Finding(
                            check_id="IAM_006",
                            service="IAM",
                            severity=Severity.MEDIUM,
                            title=f"IAM Access Key {key_num} Not Used in {age_days} Days",
                            resource_arn=row.get("arn", "unknown"),
                            region="global",
                            description=f"User '{row['user']}' has access key {key_num} last used {age_days} days ago.",
                            recommendation=f"Rotate or remove access keys not used in over {STALE_DAYS} days.",
                        ))
                except (ValueError, TypeError):
                    pass
        return findings

    def _check_password_rotation(self, cred_report: list[dict]) -> list[Finding]:
        findings = []
        now = datetime.now(timezone.utc)
        for row in cred_report:
            if row["user"] == "<root_account>":
                continue
            if row.get("password_enabled", "false").lower() != "true":
                continue
            last_changed = row.get("password_last_changed", "N/A")
            if last_changed == "N/A" or last_changed == "not_supported":
                continue
            try:
                last_dt = datetime.fromisoformat(last_changed.replace("+00:00", "+00:00"))
                if not last_dt.tzinfo:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                age_days = (now - last_dt).days
                if age_days > STALE_DAYS:
                    findings.append(Finding(
                        check_id="IAM_007",
                        service="IAM",
                        severity=Severity.MEDIUM,
                        title=f"IAM User Password Not Rotated in {age_days} Days",
                        resource_arn=row.get("arn", "unknown"),
                        region="global",
                        description=f"User '{row['user']}' has not changed their password in {age_days} days.",
                        recommendation=f"Require password rotation every {STALE_DAYS} days or less.",
                    ))
            except (ValueError, TypeError):
                pass
        return findings
