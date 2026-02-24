from dataclasses import dataclass, field, asdict
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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    account_id: str
    scan_time: str
    findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {
                "account_id": self.account_id,
                "scan_time": self.scan_time,
                "total_findings": len(self.findings),
                "by_severity": {
                    s.value: sum(1 for f in self.findings if f.severity == s)
                    for s in Severity
                },
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=2,
        )
