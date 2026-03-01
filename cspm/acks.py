"""Acknowledgment (suppression) system for CSPM findings.

Acks are stored in a JSON file (default: .cspm-ack.json) and matched
against findings by check_id and resource_arn. Both fields support "*"
as a wildcard. Acks can optionally carry an expiry date after which they
stop matching so suppressions don't silently live forever.
"""

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cspm.models import Finding

DEFAULT_ACK_FILE = ".cspm-ack.json"


@dataclass
class Ack:
    check_id: str       # exact check ID or "*" for any
    resource_arn: str   # exact resource ARN or "*" for any
    reason: str
    acknowledged_by: str = ""
    acknowledged_at: str = ""
    expires: str | None = None  # ISO-8601 date, e.g. "2027-01-01"

    def matches(self, finding: "Finding") -> bool:
        if self.check_id != "*" and self.check_id != finding.check_id:
            return False
        if self.resource_arn != "*" and self.resource_arn != finding.resource_arn:
            return False
        if self.expires:
            try:
                exp = datetime.fromisoformat(self.expires)
                if not exp.tzinfo:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    return False
            except ValueError:
                print(
                    f"[acks] Warning: invalid expiry date '{self.expires}' on ack "
                    f"{self.check_id}/{self.resource_arn} — treating as non-expiring.",
                    file=sys.stderr,
                )
        return True

    def to_dict(self) -> dict:
        d = {
            "check_id": self.check_id,
            "resource_arn": self.resource_arn,
            "reason": self.reason,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at,
        }
        if self.expires:
            d["expires"] = self.expires
        return d


def load_acks(path: str) -> list[Ack]:
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return [Ack(**item) for item in data]
    except (json.JSONDecodeError, TypeError, KeyError) as e:
        raise ValueError(f"Invalid ack file '{path}': {e}") from e


def save_acks(acks: list[Ack], path: str) -> None:
    data = json.dumps([a.to_dict() for a in acks], indent=2)
    dir_ = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def filter_findings(
    findings: list, acks: list[Ack]
) -> tuple[list, list]:
    """Split findings into (active, acknowledged).

    Acknowledged findings are those matched by at least one non-expired Ack.
    """
    if not acks:
        return findings, []
    active, acked = [], []
    for f in findings:
        if any(a.matches(f) for a in acks):
            acked.append(f)
        else:
            active.append(f)
    return active, acked
