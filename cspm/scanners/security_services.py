import logging

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class SecurityServicesScanner(BaseScanner):
    """Checks whether key AWS detective/preventive security services are enabled."""

    service_name = "SecurityServices"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_guardduty())
        findings.extend(self._check_config())
        findings.extend(self._check_access_analyzer())
        findings.extend(self._check_security_hub())
        findings.extend(self._check_macie())
        return findings

    def _check_guardduty(self) -> list[Finding]:
        """SEC_001 - GuardDuty Not Enabled."""
        try:
            gd = self._get_client("guardduty")
            detector_ids = gd.list_detectors().get("DetectorIds", [])
            if not detector_ids:
                return [Finding(
                    check_id="SEC_001",
                    service="SecurityServices",
                    severity=Severity.HIGH,
                    title="GuardDuty Not Enabled",
                    resource_arn=f"arn:aws:guardduty:{self.region}",
                    region=self.region,
                    description=(
                        f"Amazon GuardDuty is not enabled in {self.region}. "
                        f"GuardDuty provides continuous threat detection — without it, "
                        f"credential compromise, crypto-mining, and C2 callbacks go undetected."
                    ),
                    recommendation=(
                        "Enable GuardDuty in all active regions. "
                        "In multi-account environments, delegate administration to a security account."
                    ),
                )]
            for detector_id in detector_ids:
                det = gd.get_detector(DetectorId=detector_id)
                if det.get("Status") != "ENABLED":
                    return [Finding(
                        check_id="SEC_001",
                        service="SecurityServices",
                        severity=Severity.HIGH,
                        title="GuardDuty Detector Is Disabled",
                        resource_arn=f"arn:aws:guardduty:{self.region}:{detector_id}",
                        region=self.region,
                        description=(
                            f"GuardDuty detector '{detector_id}' exists in {self.region} "
                            f"but has been disabled. Threat detection is currently inactive."
                        ),
                        recommendation="Re-enable the GuardDuty detector to resume continuous threat monitoring.",
                    )]
        except ClientError as e:
            logger.warning("GuardDuty check failed in %s: %s", self.region, e)
        return []

    def _check_config(self) -> list[Finding]:
        """SEC_002 - AWS Config Not Enabled or Not Recording."""
        try:
            cfg = self._get_client("config")
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                return [Finding(
                    check_id="SEC_002",
                    service="SecurityServices",
                    severity=Severity.MEDIUM,
                    title="AWS Config Not Enabled",
                    resource_arn=f"arn:aws:config:{self.region}",
                    region=self.region,
                    description=(
                        f"AWS Config has no configuration recorder in {self.region}. "
                        f"Without Config, there is no audit trail of resource configuration changes "
                        f"and no basis for compliance rules."
                    ),
                    recommendation=(
                        "Enable AWS Config with a configuration recorder and delivery channel. "
                        "Required for CIS, PCI-DSS, and SOC 2 compliance."
                    ),
                )]
            statuses = cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
            for status in statuses:
                if not status.get("recording", False):
                    return [Finding(
                        check_id="SEC_002",
                        service="SecurityServices",
                        severity=Severity.MEDIUM,
                        title="AWS Config Recorder Not Recording",
                        resource_arn=f"arn:aws:config:{self.region}",
                        region=self.region,
                        description=(
                            f"AWS Config recorder '{status.get('name')}' in {self.region} "
                            f"exists but is not actively recording. Resource changes are not being tracked."
                        ),
                        recommendation="Start the AWS Config configuration recorder.",
                    )]
        except ClientError as e:
            logger.warning("AWS Config check failed in %s: %s", self.region, e)
        return []

    def _check_access_analyzer(self) -> list[Finding]:
        """SEC_003 - IAM Access Analyzer Not Enabled."""
        try:
            aa = self._get_client("accessanalyzer")
            analyzers = aa.list_analyzers().get("analyzers", [])
            active = [a for a in analyzers if a.get("status") == "ACTIVE"]
            if not active:
                return [Finding(
                    check_id="SEC_003",
                    service="SecurityServices",
                    severity=Severity.MEDIUM,
                    title="IAM Access Analyzer Not Enabled",
                    resource_arn=f"arn:aws:access-analyzer:{self.region}",
                    region=self.region,
                    description=(
                        f"No active IAM Access Analyzer exists in {self.region}. "
                        f"Access Analyzer identifies S3 buckets, IAM roles, KMS keys, and Lambda functions "
                        f"that are shared with external entities or are publicly accessible."
                    ),
                    recommendation=(
                        "Create an IAM Access Analyzer with zone of trust set to your organization "
                        "or account. Review all findings to identify unintended external access."
                    ),
                )]
        except ClientError as e:
            logger.warning("Access Analyzer check failed in %s: %s", self.region, e)
        return []

    def _check_security_hub(self) -> list[Finding]:
        """SEC_004 - Security Hub Not Enabled."""
        try:
            sh = self._get_client("securityhub")
            sh.describe_hub()
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "InvalidAccessException", "ResourceNotFoundException"
            ):
                return [Finding(
                    check_id="SEC_004",
                    service="SecurityServices",
                    severity=Severity.LOW,
                    title="Security Hub Not Enabled",
                    resource_arn=f"arn:aws:securityhub:{self.region}",
                    region=self.region,
                    description=(
                        f"AWS Security Hub is not enabled in {self.region}. "
                        f"Security Hub aggregates findings from GuardDuty, Inspector, Macie, "
                        f"and Config into a centralised view and applies security standards."
                    ),
                    recommendation=(
                        "Enable Security Hub and subscribe to the AWS Foundational Security Best Practices "
                        "standard. In multi-account environments, delegate administration to a security account."
                    ),
                )]
            logger.warning("Security Hub check failed in %s: %s", self.region, e)
        return []

    def _check_macie(self) -> list[Finding]:
        """SEC_005 - Amazon Macie Not Enabled."""
        try:
            macie = self._get_client("macie2")
            resp = macie.get_macie_session()
            if resp.get("status") != "ENABLED":
                return self._macie_not_enabled_finding()
        except ClientError as e:
            # Macie returns AccessDeniedException when not subscribed
            if e.response["Error"]["Code"] == "AccessDeniedException":
                return self._macie_not_enabled_finding()
            logger.warning("Macie check failed in %s: %s", self.region, e)
        return []

    def _macie_not_enabled_finding(self) -> list[Finding]:
        return [Finding(
            check_id="SEC_005",
            service="SecurityServices",
            severity=Severity.LOW,
            title="Amazon Macie Not Enabled",
            resource_arn=f"arn:aws:macie2:{self.region}",
            region=self.region,
            description=(
                f"Amazon Macie is not enabled in {self.region}. "
                f"Macie uses machine learning to automatically discover and classify sensitive data "
                f"(PII, credentials, financial data) stored in S3."
            ),
            recommendation=(
                "Enable Amazon Macie to identify S3 buckets containing sensitive data. "
                "Start with a discovery job on your most sensitive buckets."
            ),
        )]
