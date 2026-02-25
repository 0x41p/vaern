from dataclasses import dataclass, field
from enum import Enum
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass
class Finding:
    check_id: str
    service: str
    severity: Severity
    title: str
    resource_arn: str
    region: str
    description: str
    recommendation: str
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    exploit_available: bool | None = None
    fix_available: bool | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_in_version: str | None = None

    def to_dict(self) -> dict:
        d = {
            "check_id": self.check_id,
            "service": self.service,
            "severity": self.severity.value,
            "title": self.title,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "description": self.description,
            "recommendation": self.recommendation,
        }
        for key in (
            "cve_id", "cvss_score", "epss_score", "exploit_available",
            "fix_available", "package_name", "package_version", "fixed_in_version",
        ):
            val = getattr(self, key)
            if val is not None:
                d[key] = val
        return d


@dataclass
class ScanResult:
    account_id: str
    scan_time: str
    findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> str:
        data = {
            "account_id": self.account_id,
            "scan_time": self.scan_time,
            "total_findings": len(self.findings),
            "by_severity": {
                s.value: sum(1 for f in self.findings if f.severity == s)
                for s in Severity
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        vuln_findings = [f for f in self.findings if f.cve_id is not None]
        if vuln_findings:
            data["vulnerability_summary"] = {
                "total_cves": len(vuln_findings),
                "exploitable": sum(
                    1 for f in vuln_findings if f.exploit_available
                ),
                "fixable": sum(
                    1 for f in vuln_findings if f.fix_available
                ),
            }
        return json.dumps(data, indent=2)
