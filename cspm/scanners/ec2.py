import logging

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

logger = logging.getLogger(__name__)

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

INSPECTOR_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.LOW,
    "UNTRIAGED": Severity.MEDIUM,
}

# When a CVE is both exploitable and internet-reachable, escalate one tier
SEVERITY_ESCALATION = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


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

        # Vulnerability scanning — reuse already-fetched SG and instance data
        sg_exposure = self._build_sg_exposure_map(security_groups)
        instance_network = self._build_instance_network_map(instances)
        ip_to_instance = self._build_ip_to_instance_map(instances)
        lb_instance_map = self._build_lb_instance_map(ip_to_instance)
        findings.extend(self._scan_ec2_vulnerabilities(sg_exposure, instance_network, lb_instance_map))

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

    # ------------------------------------------------------------------ #
    # Reachability map builders (use already-fetched data, no extra calls)
    # ------------------------------------------------------------------ #

    def _build_sg_exposure_map(
        self, security_groups: list[dict]
    ) -> dict[str, list[str]]:
        """Map SG ID → list of internet-exposed port descriptions.

        Only SGs with at least one inbound rule open to 0.0.0.0/0 or ::/0
        are included. Port descriptions look like "TCP 22", "UDP 53-54",
        or "all ports".
        """
        exposure: dict[str, list[str]] = {}
        for sg in security_groups:
            sg_id = sg["GroupId"]
            exposed_ports: list[str] = []
            for rule in sg.get("IpPermissions", []):
                open_cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
                open_cidrs |= {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
                if not (OPEN_CIDRS & open_cidrs):
                    continue
                protocol = str(rule.get("IpProtocol", ""))
                if protocol == "-1":
                    exposed_ports.append("all ports")
                    break
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                if protocol in ("tcp", "6"):
                    label = "TCP"
                elif protocol in ("udp", "17"):
                    label = "UDP"
                else:
                    label = protocol.upper()
                if from_port == to_port:
                    exposed_ports.append(f"{label} {from_port}")
                else:
                    exposed_ports.append(f"{label} {from_port}-{to_port}")
            if exposed_ports:
                exposure[sg_id] = exposed_ports
        return exposure

    def _build_instance_network_map(
        self, instances: list[dict]
    ) -> dict[str, dict]:
        """Map instance ID → {sg_ids, public_ip}."""
        network: dict[str, dict] = {}
        for instance in instances:
            network[instance["InstanceId"]] = {
                "sg_ids": {g["GroupId"] for g in instance.get("SecurityGroups", [])},
                "public_ip": instance.get("PublicIpAddress"),
            }
        return network

    def _build_ip_to_instance_map(self, instances: list[dict]) -> dict[str, str]:
        """Map every private IP address → instance ID.

        Covers primary and secondary IPs across all ENIs attached to each
        instance. Used to resolve IP-mode LB targets back to an instance ID.
        Fargate task ENIs have no EC2 instance backing them so they simply
        won't appear here — correct behaviour for an EC2 scanner.
        """
        ip_map: dict[str, str] = {}
        for instance in instances:
            iid = instance["InstanceId"]
            for nic in instance.get("NetworkInterfaces", []):
                for addr in nic.get("PrivateIpAddresses", []):
                    ip = addr.get("PrivateIpAddress")
                    if ip:
                        ip_map[ip] = iid
        return ip_map

    def _build_lb_instance_map(self, ip_to_instance: dict[str, str]) -> dict[str, list[str]]:
        """Map instance ID → list of internet-facing LB DNS names that target it.

        Covers both ELBv2 (ALB/NLB) and Classic ELB. Only instance-mode
        target groups are walked; IP-mode targets are skipped. Failures are
        silently swallowed so a missing permission never blocks the main scan.
        """
        # Use a set per instance to avoid duplicates when an instance appears
        # in multiple target groups of the same LB.
        result: dict[str, set[str]] = {}

        # ── ELBv2 (ALB / NLB) ────────────────────────────────────────────
        try:
            elbv2 = self._get_client("elbv2")
            lb_paginator = elbv2.get_paginator("describe_load_balancers")
            for page in lb_paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    if lb.get("Scheme") != "internet-facing":
                        continue
                    lb_dns = lb["DNSName"]
                    lb_arn = lb["LoadBalancerArn"]
                    try:
                        tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
                        for tg in tg_resp.get("TargetGroups", []):
                            target_type = tg.get("TargetType")
                            if target_type not in ("instance", "ip"):
                                continue  # lambda targets have no EC2 instance
                            tg_arn = tg["TargetGroupArn"]
                            try:
                                health = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                                for thd in health.get("TargetHealthDescriptions", []):
                                    state = thd.get("TargetHealth", {}).get("State", "")
                                    if state not in ("healthy", "initial", "draining"):
                                        continue
                                    target_id = thd["Target"]["Id"]
                                    if target_type == "instance":
                                        result.setdefault(target_id, set()).add(lb_dns)
                                    else:
                                        # IP mode: resolve private IP → instance ID.
                                        # Fargate task IPs won't be in the map — skipped.
                                        iid = ip_to_instance.get(target_id)
                                        if iid:
                                            result.setdefault(iid, set()).add(lb_dns)
                            except ClientError:
                                pass
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning("ELBv2 lookup for reachability failed: %s", e)

        # ── Classic ELB ───────────────────────────────────────────────────
        try:
            elb = self._get_client("elb")
            clb_paginator = elb.get_paginator("describe_load_balancers")
            for page in clb_paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):
                    if lb.get("Scheme") != "internet-facing":
                        continue
                    lb_dns = lb["DNSName"]
                    for inst in lb.get("Instances", []):
                        iid = inst["InstanceId"]
                        result.setdefault(iid, set()).add(lb_dns)
        except ClientError as e:
            logger.warning("Classic ELB lookup for reachability failed: %s", e)

        return {iid: sorted(dns_set) for iid, dns_set in result.items()}

    def _instance_reachability(
        self,
        instance_id: str,
        instance_network: dict[str, dict],
        sg_exposure: dict[str, list[str]],
        lb_instance_map: dict[str, list[str]],
    ) -> tuple[bool, list[str], list[str]]:
        """Return (is_internet_reachable, direct_ports, via_lb_dns_names).

        direct_ports   – ports open to 0.0.0.0/0/::/0 on the instance's own SGs
                         (only populated when the instance also has a public IP).
        via_lb_dns_names – DNS names of internet-facing LBs that target this instance
                           (populated even when the instance has no public IP).
        """
        direct_ports: list[str] = []
        via_lbs: list[str] = lb_instance_map.get(instance_id, [])

        net = instance_network.get(instance_id)
        if net and net["public_ip"]:
            exposed: list[str] = []
            for sg_id in net["sg_ids"]:
                exposed.extend(sg_exposure.get(sg_id, []))
            seen: set[str] = set()
            direct_ports = [p for p in exposed if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]

        is_reachable = bool(direct_ports or via_lbs)
        return is_reachable, direct_ports, via_lbs

    # ------------------------------------------------------------------ #
    # EC2 vulnerability scanning via Inspector v2
    # ------------------------------------------------------------------ #

    def _scan_ec2_vulnerabilities(
        self,
        sg_exposure: dict[str, list[str]],
        instance_network: dict[str, dict],
        lb_instance_map: dict[str, list[str]],
    ) -> list[Finding]:
        """Query Inspector v2 for EC2 package CVEs, enriched with reachability."""
        try:
            inspector = self._get_client("inspector2")
            findings: list[Finding] = []
            paginator = inspector.get_paginator("list_findings")
            filter_criteria = {
                "resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}],
                "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            }
            for page in paginator.paginate(filterCriteria=filter_criteria):
                for f in page.get("findings", []):
                    finding = self._parse_ec2_inspector_finding(
                        f, sg_exposure, instance_network, lb_instance_map
                    )
                    if finding:
                        findings.append(finding)
            return findings
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "AccessDeniedException", "ValidationException"
            ):
                logger.warning(
                    "Inspector v2 unavailable; EC2 vulnerability scanning skipped."
                )
                return []
            raise

    def _parse_ec2_inspector_finding(
        self,
        f: dict,
        sg_exposure: dict[str, list[str]],
        instance_network: dict[str, dict],
        lb_instance_map: dict[str, list[str]],
    ) -> Finding | None:
        vuln = f.get("packageVulnerabilityDetails", {})
        cve_id = vuln.get("vulnerabilityId", "")
        if not cve_id:
            return None

        severity = INSPECTOR_SEVERITY_MAP.get(f.get("severity", "MEDIUM"), Severity.MEDIUM)

        cvss_score = None
        if f.get("inspectorScore") is not None:
            cvss_score = float(f["inspectorScore"])
        elif vuln.get("cvss"):
            for entry in vuln["cvss"]:
                if "baseScore" in entry:
                    cvss_score = float(entry["baseScore"])
                    break

        epss_score = None
        if f.get("epss") and "score" in f["epss"]:
            epss_score = float(f["epss"]["score"])

        exploit_available = None
        if f.get("exploitAvailable") is not None:
            exploit_available = f["exploitAvailable"] == "YES"

        fix_available = None
        if f.get("fixAvailable") is not None:
            fix_available = f["fixAvailable"] == "YES"

        package_name = package_version = fixed_in_version = None
        if vuln.get("vulnerablePackages"):
            pkg = vuln["vulnerablePackages"][0]
            package_name = pkg.get("name")
            package_version = pkg.get("version")
            fixed_in_version = pkg.get("fixedInVersion")

        resources = f.get("resources", [])
        resource_arn = resources[0]["id"] if resources else "unknown"
        # ARN format: arn:aws:ec2:<region>:<account>:instance/i-xxxx
        instance_id = resource_arn.rsplit("/", 1)[-1]

        is_reachable, direct_ports, via_lbs = self._instance_reachability(
            instance_id, instance_network, sg_exposure, lb_instance_map
        )

        # Escalate severity when exploit exists AND instance is reachable from internet
        if is_reachable and exploit_available:
            severity = SEVERITY_ESCALATION.get(severity, severity)

        # Description
        description = f"{cve_id} found on EC2 instance {instance_id}"
        if package_name:
            description += f" (package: {package_name}"
            if package_version:
                description += f" {package_version}"
            description += ")"
        if direct_ports:
            description += (
                f". INTERNET REACHABLE (direct): public IP with inbound rules"
                f" open to 0.0.0.0/0/::/0 on {', '.join(direct_ports)}"
            )
        if via_lbs:
            description += (
                f". INTERNET REACHABLE (via load balancer): "
                + ", ".join(via_lbs)
            )
        if not is_reachable:
            description += ". Not internet-reachable (private subnet, no targeting LB found)"

        # Recommendation
        recommendation = f"Upgrade {package_name or 'affected package'}"
        if fixed_in_version:
            recommendation += f" to {fixed_in_version}"
        recommendation += "."
        if is_reachable and exploit_available:
            reach_detail = ", ".join(direct_ports) if direct_ports else ", ".join(via_lbs)
            recommendation += (
                f" URGENT: public exploit exists and instance is internet-reachable"
                f" ({reach_detail}). Patch immediately."
            )
            if direct_ports:
                recommendation += " Restrict inbound SG rules to trusted IPs."
            if via_lbs:
                recommendation += " Review LB target group membership and WAF rules."
        elif exploit_available:
            recommendation += " A public exploit exists — prioritise patching."
        elif is_reachable:
            if direct_ports:
                recommendation += (
                    f" Instance is directly internet-reachable ({', '.join(direct_ports)});"
                    " restrict inbound rules to trusted IPs while patching."
                )
            if via_lbs:
                recommendation += (
                    f" Instance receives internet traffic via load balancer(s): {', '.join(via_lbs)}."
                    " Review WAF rules and patch promptly."
                )

        check_id = "EC2_V" + cve_id.replace("CVE-", "").replace("-", "_")

        return Finding(
            check_id=check_id,
            service="EC2",
            severity=severity,
            title=f"{cve_id} in {instance_id}",
            resource_arn=resource_arn,
            region=self.region,
            description=description,
            recommendation=recommendation,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            exploit_available=exploit_available,
            fix_available=fix_available,
            package_name=package_name,
            package_version=package_version,
            fixed_in_version=fixed_in_version,
            direct_ports=direct_ports or None,
            via_lbs=via_lbs or None,
        )

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
