import logging
from collections import defaultdict

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

SEVERITY_ESCALATION = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


@register_scanner
class ECSFargateScanner(BaseScanner):
    service_name = "ECSFargate"

    def run(self) -> list[Finding]:
        ecs = self._get_client("ecs")

        cluster_arns = self._list_clusters(ecs)
        if not cluster_arns:
            return []

        tasks = self._get_running_fargate_tasks(ecs, cluster_arns)
        if not tasks:
            return []

        inspector_by_digest = self._get_inspector_findings_by_digest()
        if not inspector_by_digest:
            return []

        # Build reachability maps before iterating tasks so we make bulk
        # API calls rather than one per task.
        eni_network = self._build_eni_network_map(tasks)
        service_lb_map = self._build_service_lb_map(ecs, cluster_arns)

        findings: list[Finding] = []
        # Deduplicate: one finding per (CVE, service group) — all tasks in
        # a service share the same image and the same LB reachability.
        seen: set[tuple[str, str]] = set()

        for task in tasks:
            cluster_name = task["clusterArn"].rsplit("/", 1)[-1]
            service_group = task.get("group", "")
            reachability = self._task_reachability(task, service_group, eni_network, service_lb_map)

            for container in task.get("containers", []):
                digest = container.get("imageDigest", "")
                if not digest or digest not in inspector_by_digest:
                    continue

                for insp in inspector_by_digest[digest]:
                    cve_id = (
                        insp.get("packageVulnerabilityDetails", {})
                        .get("vulnerabilityId", "")
                    )
                    if not cve_id:
                        continue

                    dedup_key = (cve_id, service_group or task["taskArn"])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    finding = self._make_finding(
                        insp, cve_id, task, cluster_name,
                        service_group, container, reachability,
                    )
                    if finding:
                        findings.append(finding)

        return findings

    # ------------------------------------------------------------------ #
    # ECS data helpers
    # ------------------------------------------------------------------ #

    def _list_clusters(self, ecs) -> list[str]:
        arns: list[str] = []
        for page in ecs.get_paginator("list_clusters").paginate():
            arns.extend(page.get("clusterArns", []))
        return arns

    def _get_running_fargate_tasks(
        self, ecs, cluster_arns: list[str]
    ) -> list[dict]:
        tasks: list[dict] = []
        for cluster_arn in cluster_arns:
            task_arns: list[str] = []
            paginator = ecs.get_paginator("list_tasks")
            for page in paginator.paginate(
                cluster=cluster_arn,
                launchType="FARGATE",
                desiredStatus="RUNNING",
            ):
                task_arns.extend(page.get("taskArns", []))

            for i in range(0, len(task_arns), 100):
                batch = task_arns[i : i + 100]
                try:
                    resp = ecs.describe_tasks(cluster=cluster_arn, tasks=batch)
                    tasks.extend(resp.get("tasks", []))
                except ClientError as e:
                    logger.warning("describe_tasks failed for %s: %s", cluster_arn, e)
        return tasks

    # ------------------------------------------------------------------ #
    # Inspector v2
    # ------------------------------------------------------------------ #

    def _get_inspector_findings_by_digest(self) -> dict[str, list[dict]]:
        """Fetch all active ECR image CVEs from Inspector, keyed by image digest."""
        try:
            inspector = self._get_client("inspector2")
            by_digest: dict[str, list[dict]] = defaultdict(list)
            paginator = inspector.get_paginator("list_findings")
            filter_criteria = {
                "resourceType": [
                    {"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}
                ],
                "findingType": [
                    {"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}
                ],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            }
            for page in paginator.paginate(filterCriteria=filter_criteria):
                for f in page.get("findings", []):
                    resources = f.get("resources", [])
                    if not resources:
                        continue
                    digest = (
                        resources[0]
                        .get("details", {})
                        .get("awsEcrContainerImage", {})
                        .get("imageDigest", "")
                    )
                    if digest:
                        by_digest[digest].append(f)
            return dict(by_digest)
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "AccessDeniedException",
                "ValidationException",
            ):
                logger.warning(
                    "Inspector v2 unavailable; ECS Fargate vulnerability scanning skipped."
                )
                return {}
            raise

    # ------------------------------------------------------------------ #
    # Reachability — bulk ENI lookup then per-task join
    # ------------------------------------------------------------------ #

    def _build_eni_network_map(
        self, tasks: list[dict]
    ) -> dict[str, dict]:
        """Fetch all task ENIs in bulk and return eni_id → {public_ip, sg_ids}."""
        eni_ids: list[str] = []
        for task in tasks:
            eni_id = self._task_eni_id(task)
            if eni_id:
                eni_ids.append(eni_id)

        if not eni_ids:
            return {}

        ec2 = self._get_client("ec2")
        eni_map: dict[str, dict] = {}
        # describe_network_interfaces accepts up to 1000 at a time
        for i in range(0, len(eni_ids), 200):
            batch = eni_ids[i : i + 200]
            try:
                resp = ec2.describe_network_interfaces(NetworkInterfaceIds=batch)
                for eni in resp.get("NetworkInterfaces", []):
                    eni_map[eni["NetworkInterfaceId"]] = {
                        "public_ip": eni.get("Association", {}).get("PublicIp"),
                        "sg_ids": [g["GroupId"] for g in eni.get("Groups", [])],
                    }
            except ClientError as e:
                logger.warning("describe_network_interfaces failed: %s", e)

        # Fetch SG rules for all unique SGs in one shot
        all_sg_ids = list(
            {sg for eni in eni_map.values() for sg in eni["sg_ids"]}
        )
        sg_exposure = self._fetch_sg_exposure(ec2, all_sg_ids)

        # Attach resolved port exposure back into eni_map
        for eni in eni_map.values():
            ports: list[str] = []
            for sg_id in eni["sg_ids"]:
                ports.extend(sg_exposure.get(sg_id, []))
            seen: set[str] = set()
            eni["exposed_ports"] = [
                p for p in ports if not (p in seen or seen.add(p))  # type: ignore[func-returns-value]
            ]

        return eni_map

    def _fetch_sg_exposure(
        self, ec2, sg_ids: list[str]
    ) -> dict[str, list[str]]:
        """Return sg_id → list of port descriptions open to internet."""
        if not sg_ids:
            return {}
        exposure: dict[str, list[str]] = {}
        for i in range(0, len(sg_ids), 200):
            batch = sg_ids[i : i + 200]
            try:
                resp = ec2.describe_security_groups(GroupIds=batch)
                for sg in resp.get("SecurityGroups", []):
                    ports: list[str] = []
                    for rule in sg.get("IpPermissions", []):
                        ports.extend(self._rule_exposed_ports(rule))
                    if ports:
                        exposure[sg["GroupId"]] = ports
            except ClientError as e:
                logger.warning("describe_security_groups failed: %s", e)
        return exposure

    @staticmethod
    def _rule_exposed_ports(rule: dict) -> list[str]:
        """Port descriptions for rules open to 0.0.0.0/0 or ::/0."""
        cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
        cidrs |= {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
        if not (OPEN_CIDRS & cidrs):
            return []
        protocol = str(rule.get("IpProtocol", ""))
        if protocol == "-1":
            return ["all ports"]
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        label = (
            "TCP" if protocol in ("tcp", "6")
            else "UDP" if protocol in ("udp", "17")
            else protocol.upper()
        )
        return [f"{label} {from_port}" if from_port == to_port
                else f"{label} {from_port}-{to_port}"]

    def _build_service_lb_map(
        self, ecs, cluster_arns: list[str]
    ) -> dict[str, list[str]]:
        """Map 'service:<name>' → [internet-facing LB DNS names]."""
        # Build target group ARN → LB DNS for internet-facing LBs
        tg_to_lb_dns = self._internet_facing_tg_map()

        result: dict[str, list[str]] = {}
        for cluster_arn in cluster_arns:
            svc_arns: list[str] = []
            for page in ecs.get_paginator("list_services").paginate(cluster=cluster_arn):
                svc_arns.extend(page.get("serviceArns", []))

            for i in range(0, len(svc_arns), 10):
                batch = svc_arns[i : i + 10]
                try:
                    resp = ecs.describe_services(cluster=cluster_arn, services=batch)
                    for svc in resp.get("services", []):
                        lb_dns: list[str] = []
                        for lb_conf in svc.get("loadBalancers", []):
                            tg_arn = lb_conf.get("targetGroupArn", "")
                            dns = tg_to_lb_dns.get(tg_arn)
                            if dns:
                                lb_dns.append(dns)
                        if lb_dns:
                            group_key = f"service:{svc['serviceName']}"
                            result[group_key] = lb_dns
                except ClientError as e:
                    logger.warning("describe_services failed for %s: %s", cluster_arn, e)

        return result

    def _internet_facing_tg_map(self) -> dict[str, str]:
        """Return target group ARN → LB DNS for internet-facing ALBs/NLBs."""
        tg_to_dns: dict[str, str] = {}
        try:
            elbv2 = self._get_client("elbv2")
            for page in elbv2.get_paginator("describe_load_balancers").paginate():
                for lb in page.get("LoadBalancers", []):
                    if lb.get("Scheme") != "internet-facing":
                        continue
                    lb_arn = lb["LoadBalancerArn"]
                    lb_dns = lb["DNSName"]
                    try:
                        tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
                        for tg in tg_resp.get("TargetGroups", []):
                            tg_to_dns[tg["TargetGroupArn"]] = lb_dns
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning("ELBv2 lookup for Fargate reachability failed: %s", e)
        return tg_to_dns

    def _task_reachability(
        self,
        task: dict,
        service_group: str,
        eni_network: dict[str, dict],
        service_lb_map: dict[str, list[str]],
    ) -> dict:
        direct_ports: list[str] = []
        eni_id = self._task_eni_id(task)
        if eni_id:
            eni = eni_network.get(eni_id, {})
            if eni.get("public_ip"):
                direct_ports = eni.get("exposed_ports", [])

        via_lbs: list[str] = service_lb_map.get(service_group, [])

        return {
            "is_reachable": bool(direct_ports or via_lbs),
            "direct_ports": direct_ports,
            "via_lbs": via_lbs,
        }

    @staticmethod
    def _task_eni_id(task: dict) -> str | None:
        for attachment in task.get("attachments", []):
            if attachment.get("type") == "ElasticNetworkInterface":
                for detail in attachment.get("details", []):
                    if detail.get("name") == "networkInterfaceId":
                        return detail.get("value")
        return None

    # ------------------------------------------------------------------ #
    # Finding construction
    # ------------------------------------------------------------------ #

    def _make_finding(
        self,
        insp: dict,
        cve_id: str,
        task: dict,
        cluster_name: str,
        service_group: str,
        container: dict,
        reachability: dict,
    ) -> Finding | None:
        vuln = insp.get("packageVulnerabilityDetails", {})

        severity = INSPECTOR_SEVERITY_MAP.get(
            insp.get("severity", "MEDIUM"), Severity.MEDIUM
        )

        cvss_score = None
        if insp.get("inspectorScore") is not None:
            cvss_score = float(insp["inspectorScore"])
        elif vuln.get("cvss"):
            for entry in vuln["cvss"]:
                if "baseScore" in entry:
                    cvss_score = float(entry["baseScore"])
                    break

        epss_score = None
        if insp.get("epss", {}).get("score") is not None:
            epss_score = float(insp["epss"]["score"])

        exploit_available = None
        if insp.get("exploitAvailable") is not None:
            exploit_available = insp["exploitAvailable"] == "YES"

        fix_available = None
        if insp.get("fixAvailable") is not None:
            fix_available = insp["fixAvailable"] == "YES"

        package_name = package_version = fixed_in_version = None
        if vuln.get("vulnerablePackages"):
            pkg = vuln["vulnerablePackages"][0]
            package_name = pkg.get("name")
            package_version = pkg.get("version")
            fixed_in_version = pkg.get("fixedInVersion")

        is_reachable = reachability["is_reachable"]
        direct_ports: list[str] = reachability["direct_ports"]
        via_lbs: list[str] = reachability["via_lbs"]

        if is_reachable and exploit_available:
            severity = SEVERITY_ESCALATION.get(severity, severity)

        service_name = (
            service_group.removeprefix("service:")
            if service_group.startswith("service:")
            else service_group or "standalone task"
        )
        image = container.get("image", "unknown")

        # Description
        description = (
            f"{cve_id} in image '{image}' running as Fargate task "
            f"in cluster '{cluster_name}', service '{service_name}'"
        )
        if package_name:
            description += f". Package: {package_name}"
            if package_version:
                description += f" {package_version}"
        if direct_ports:
            description += (
                f". INTERNET REACHABLE (direct): task has a public IP with "
                f"inbound rules open to 0.0.0.0/0 on {', '.join(direct_ports)}"
            )
        if via_lbs:
            description += (
                f". INTERNET REACHABLE (via load balancer): {', '.join(via_lbs)}"
            )
        if not is_reachable:
            description += ". Not internet-reachable"

        # Recommendation
        recommendation = f"Rebuild and redeploy the container image"
        if package_name:
            recommendation = f"Upgrade {package_name}"
            if fixed_in_version:
                recommendation += f" to {fixed_in_version}"
            recommendation += " and redeploy the ECS service with the patched image"
        recommendation += "."
        if is_reachable and exploit_available:
            reach = ", ".join(direct_ports) if direct_ports else ", ".join(via_lbs)
            recommendation += (
                f" URGENT: public exploit exists and task is internet-reachable ({reach})."
            )
            if via_lbs:
                recommendation += " Apply WAF rules to the load balancer while patching."
        elif exploit_available:
            recommendation += " A public exploit exists — prioritise remediation."
        elif is_reachable and via_lbs:
            recommendation += (
                f" Task receives internet traffic via {', '.join(via_lbs)}."
                " Consider WAF rules while patching."
            )

        check_id = "ECSF_V" + cve_id.replace("CVE-", "").replace("-", "_")

        return Finding(
            check_id=check_id,
            service="ECSFargate",
            severity=severity,
            title=f"{cve_id} in Fargate service '{service_name}' ({cluster_name})",
            resource_arn=task.get("taskArn", "unknown"),
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
