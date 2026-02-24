from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@register_scanner
class EC2Scanner(BaseScanner):
    service_name = "EC2"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = self._get_client("ec2")

        security_groups = self._describe_all_security_groups(ec2)
        vpcs = self._describe_all_vpcs(ec2)
        instances = self._describe_all_instances(ec2)

        # Track SG IDs that have wide-open findings (used by EC2_005)
        wide_open_sg_ids: set[str] = set()

        for sg in security_groups:
            sg_id = sg["GroupId"]

            sg_findings = []
            sg_findings.extend(self._check_unrestricted_ssh(sg))
            sg_findings.extend(self._check_unrestricted_rdp(sg))
            sg_findings.extend(self._check_all_inbound_traffic(sg))
            sg_findings.extend(self._check_default_sg_allows_traffic(sg))

            for f in sg_findings:
                if f.check_id in ("EC2_001", "EC2_002", "EC2_003"):
                    wide_open_sg_ids.add(sg_id)

            findings.extend(sg_findings)

        findings.extend(self._check_public_ip_wide_open_sg(ec2, instances, wide_open_sg_ids))
        findings.extend(self._check_vpc_flow_logs(ec2, vpcs))

        return findings

    # ------------------------------------------------------------------ #
    # AWS data helpers
    # ------------------------------------------------------------------ #

    def _describe_all_security_groups(self, ec2) -> list[dict]:
        groups: list[dict] = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
        return groups

    def _describe_all_vpcs(self, ec2) -> list[dict]:
        vpcs: list[dict] = []
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            vpcs.extend(page.get("Vpcs", []))
        return vpcs

    def _describe_all_instances(self, ec2) -> list[dict]:
        instances: list[dict] = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances

    # ------------------------------------------------------------------ #
    # Helper: check whether an inbound rule matches a specific port + CIDR
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rule_matches_port_open(rule: dict, port: int) -> bool:
        """Return True if the inbound rule opens *port* to 0.0.0.0/0 or ::/0."""
        protocol = str(rule.get("IpProtocol", ""))
        # IpProtocol "-1" means all traffic — covers every port
        if protocol != "-1":
            if protocol not in ("tcp", "6"):
                return False
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 0)
            if not (from_port <= port <= to_port):
                return False

        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") in OPEN_CIDRS:
                return True
        for ip_range in rule.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") in OPEN_CIDRS:
                return True
        return False

    @staticmethod
    def _rule_is_all_traffic_open(rule: dict) -> bool:
        """Return True if the rule allows ALL traffic from 0.0.0.0/0 or ::/0."""
        if str(rule.get("IpProtocol", "")) != "-1":
            return False
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") in OPEN_CIDRS:
                return True
        for ip_range in rule.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") in OPEN_CIDRS:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Check implementations
    # ------------------------------------------------------------------ #

    def _check_unrestricted_ssh(self, sg: dict) -> list[Finding]:
        """EC2_001 - Security Group Allows Unrestricted SSH (port 22)."""
        sg_id = sg["GroupId"]
        for rule in sg.get("IpPermissions", []):
            if self._rule_matches_port_open(rule, 22):
                return [Finding(
                    check_id="EC2_001",
                    service="EC2",
                    severity=Severity.CRITICAL,
                    title="Security Group Allows Unrestricted SSH",
                    resource_arn=sg_id,
                    region=self.region,
                    description=(
                        f"Security group '{sg_id}' allows inbound SSH (port 22) "
                        f"from 0.0.0.0/0 or ::/0."
                    ),
                    recommendation=(
                        "Restrict SSH access to trusted IP addresses only. "
                        "Remove the 0.0.0.0/0 and ::/0 inbound rules for port 22."
                    ),
                )]
        return []

    def _check_unrestricted_rdp(self, sg: dict) -> list[Finding]:
        """EC2_002 - Security Group Allows Unrestricted RDP (port 3389)."""
        sg_id = sg["GroupId"]
        for rule in sg.get("IpPermissions", []):
            if self._rule_matches_port_open(rule, 3389):
                return [Finding(
                    check_id="EC2_002",
                    service="EC2",
                    severity=Severity.CRITICAL,
                    title="Security Group Allows Unrestricted RDP",
                    resource_arn=sg_id,
                    region=self.region,
                    description=(
                        f"Security group '{sg_id}' allows inbound RDP (port 3389) "
                        f"from 0.0.0.0/0 or ::/0."
                    ),
                    recommendation=(
                        "Restrict RDP access to trusted IP addresses only. "
                        "Remove the 0.0.0.0/0 and ::/0 inbound rules for port 3389."
                    ),
                )]
        return []

    def _check_all_inbound_traffic(self, sg: dict) -> list[Finding]:
        """EC2_003 - Security Group Allows All Inbound Traffic."""
        sg_id = sg["GroupId"]
        for rule in sg.get("IpPermissions", []):
            if self._rule_is_all_traffic_open(rule):
                return [Finding(
                    check_id="EC2_003",
                    service="EC2",
                    severity=Severity.HIGH,
                    title="Security Group Allows All Inbound Traffic",
                    resource_arn=sg_id,
                    region=self.region,
                    description=(
                        f"Security group '{sg_id}' allows all inbound traffic "
                        f"(all ports, all protocols) from 0.0.0.0/0 or ::/0."
                    ),
                    recommendation=(
                        "Restrict inbound rules to only the ports and protocols required. "
                        "Remove the 0.0.0.0/0 and ::/0 rules that allow all traffic."
                    ),
                )]
        return []

    def _check_default_sg_allows_traffic(self, sg: dict) -> list[Finding]:
        """EC2_004 - Default Security Group Allows Traffic."""
        if sg.get("GroupName") != "default":
            return []

        sg_id = sg["GroupId"]
        inbound = sg.get("IpPermissions", [])
        outbound = sg.get("IpPermissionsEgress", [])

        if inbound or outbound:
            return [Finding(
                check_id="EC2_004",
                service="EC2",
                severity=Severity.MEDIUM,
                title="Default Security Group Allows Traffic",
                resource_arn=sg_id,
                region=self.region,
                description=(
                    f"The default security group '{sg_id}' has "
                    f"{len(inbound)} inbound and {len(outbound)} outbound rules. "
                    f"Default security groups should have no rules to prevent "
                    f"unintended network access."
                ),
                recommendation=(
                    "Remove all inbound and outbound rules from the default security group. "
                    "Create custom security groups for your resources instead."
                ),
            )]
        return []

    def _check_public_ip_wide_open_sg(
        self, ec2, instances: list[dict], wide_open_sg_ids: set[str]
    ) -> list[Finding]:
        """EC2_005 - EC2 Instance Has Public IP and Wide-Open SG."""
        findings: list[Finding] = []
        for instance in instances:
            public_ip = instance.get("PublicIpAddress")
            if not public_ip:
                continue

            instance_sg_ids = {
                g["GroupId"] for g in instance.get("SecurityGroups", [])
            }
            offending = instance_sg_ids & wide_open_sg_ids
            if not offending:
                continue

            instance_id = instance["InstanceId"]
            owner_id = instance.get("OwnerId", "unknown")
            instance_arn = (
                f"arn:aws:ec2:{self.region}:{owner_id}:instance/{instance_id}"
            )

            findings.append(Finding(
                check_id="EC2_005",
                service="EC2",
                severity=Severity.HIGH,
                title="EC2 Instance Has Public IP and Wide-Open Security Group",
                resource_arn=instance_arn,
                region=self.region,
                description=(
                    f"EC2 instance '{instance_id}' has public IP {public_ip} and is "
                    f"associated with wide-open security group(s): "
                    f"{', '.join(sorted(offending))}."
                ),
                recommendation=(
                    "Remove the public IP if not needed, or restrict the security group "
                    "rules to only the required ports and trusted IP ranges."
                ),
            ))
        return findings

    def _check_vpc_flow_logs(self, ec2, vpcs: list[dict]) -> list[Finding]:
        """EC2_006 - VPC Flow Logs Not Enabled."""
        findings: list[Finding] = []
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            try:
                resp = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )
                flow_logs = resp.get("FlowLogs", [])
            except ClientError:
                flow_logs = []

            if not flow_logs:
                findings.append(Finding(
                    check_id="EC2_006",
                    service="EC2",
                    severity=Severity.MEDIUM,
                    title="VPC Flow Logs Not Enabled",
                    resource_arn=vpc_id,
                    region=self.region,
                    description=(
                        f"VPC '{vpc_id}' does not have flow logs enabled. "
                        f"Flow logs capture information about IP traffic going to "
                        f"and from network interfaces in the VPC."
                    ),
                    recommendation=(
                        "Enable VPC flow logs to capture network traffic metadata. "
                        "Send logs to CloudWatch Logs or S3 for analysis and monitoring."
                    ),
                ))
        return findings
