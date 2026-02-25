from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

SECRET_KEY_PATTERNS = {"SECRET", "PASSWORD", "API_KEY", "TOKEN", "PRIVATE_KEY"}


@register_scanner
class ECSScanner(BaseScanner):
    service_name = "ECS"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        ecs = self._get_client("ecs")
        account_id = self.session.client("sts").get_caller_identity()["Account"]

        # Cluster-level checks
        cluster_arns = self._list_all_clusters(ecs)
        clusters = self._describe_clusters(ecs, cluster_arns) if cluster_arns else []
        for cluster in clusters:
            findings.extend(self._check_container_insights(cluster))

        # Task definition checks
        task_def_arns = self._list_all_task_definitions(ecs)
        for td_arn in task_def_arns:
            try:
                resp = ecs.describe_task_definition(taskDefinition=td_arn)
                td = resp["taskDefinition"]
            except ClientError:
                continue

            findings.extend(self._check_privileged_containers(td))
            findings.extend(self._check_root_user(td))
            findings.extend(self._check_host_network_mode(td))
            findings.extend(self._check_readonly_root_fs(td))
            findings.extend(self._check_env_secrets(td))
            findings.extend(self._check_logging(td))

        # Service-level checks
        for cluster_arn in cluster_arns:
            service_arns = self._list_all_services(ecs, cluster_arn)
            if service_arns:
                services = self._describe_services(ecs, cluster_arn, service_arns)
                for svc in services:
                    findings.extend(self._check_public_ip(svc))

        return findings

    # ------------------------------------------------------------------ #
    # AWS data helpers
    # ------------------------------------------------------------------ #

    def _list_all_clusters(self, ecs) -> list[str]:
        arns: list[str] = []
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            arns.extend(page.get("clusterArns", []))
        return arns

    def _describe_clusters(self, ecs, cluster_arns: list[str]) -> list[dict]:
        # describe_clusters accepts up to 100 ARNs at a time
        clusters: list[dict] = []
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i : i + 100]
            resp = ecs.describe_clusters(
                clusters=batch, include=["SETTINGS"]
            )
            clusters.extend(resp.get("clusters", []))
        return clusters

    def _list_all_task_definitions(self, ecs) -> list[str]:
        arns: list[str] = []
        paginator = ecs.get_paginator("list_task_definitions")
        for page in paginator.paginate(status="ACTIVE"):
            arns.extend(page.get("taskDefinitionArns", []))
        return arns

    def _list_all_services(self, ecs, cluster_arn: str) -> list[str]:
        arns: list[str] = []
        paginator = ecs.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster_arn):
            arns.extend(page.get("serviceArns", []))
        return arns

    def _describe_services(
        self, ecs, cluster_arn: str, service_arns: list[str]
    ) -> list[dict]:
        # describe_services accepts up to 10 ARNs at a time
        services: list[dict] = []
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            resp = ecs.describe_services(cluster=cluster_arn, services=batch)
            services.extend(resp.get("services", []))
        return services

    # ------------------------------------------------------------------ #
    # Check implementations
    # ------------------------------------------------------------------ #

    def _check_privileged_containers(self, td: dict) -> list[Finding]:
        """ECS_001 - Privileged containers in task definition."""
        td_arn = td["taskDefinitionArn"]
        privileged = []
        for container in td.get("containerDefinitions", []):
            if container.get("privileged", False):
                privileged.append(container["name"])

        if privileged:
            return [Finding(
                check_id="ECS_001",
                service="ECS",
                severity=Severity.CRITICAL,
                title="ECS Task Definition Has Privileged Containers",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' has privileged containers: "
                    f"{', '.join(privileged)}. Privileged containers have root-level "
                    f"access to the host and bypass most security controls."
                ),
                recommendation=(
                    "Remove the 'privileged' flag from container definitions. "
                    "Use specific Linux capabilities via 'linuxParameters.capabilities' "
                    "if elevated permissions are required."
                ),
            )]
        return []

    def _check_root_user(self, td: dict) -> list[Finding]:
        """ECS_002 - Containers configured to run as root user."""
        td_arn = td["taskDefinitionArn"]
        root_containers = []
        for container in td.get("containerDefinitions", []):
            user = container.get("user", "")
            if user in ("root", "0"):
                root_containers.append(container["name"])

        if root_containers:
            return [Finding(
                check_id="ECS_002",
                service="ECS",
                severity=Severity.HIGH,
                title="ECS Task Definition Runs Containers as Root",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' explicitly runs containers as "
                    f"root: {', '.join(root_containers)}."
                ),
                recommendation=(
                    "Set the 'user' parameter to a non-root user in container "
                    "definitions, or use 'linuxParameters.initProcessEnabled' with "
                    "a non-root user in the Dockerfile."
                ),
            )]
        return []

    def _check_host_network_mode(self, td: dict) -> list[Finding]:
        """ECS_003 - Task definition uses host network mode."""
        td_arn = td["taskDefinitionArn"]
        if td.get("networkMode") == "host":
            return [Finding(
                check_id="ECS_003",
                service="ECS",
                severity=Severity.HIGH,
                title="ECS Task Definition Uses Host Network Mode",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' uses 'host' network mode, which "
                    f"shares the host's network namespace. Containers can access "
                    f"all host network interfaces and services bound to localhost."
                ),
                recommendation=(
                    "Use 'awsvpc' network mode for Fargate tasks or 'bridge' mode "
                    "for EC2 tasks to provide network isolation."
                ),
            )]
        return []

    def _check_public_ip(self, service: dict) -> list[Finding]:
        """ECS_004 - ECS service assigns public IPs."""
        svc_name = service.get("serviceName", "unknown")
        svc_arn = service.get("serviceArn", "unknown")

        network_config = service.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})
        if awsvpc_config.get("assignPublicIp") == "ENABLED":
            return [Finding(
                check_id="ECS_004",
                service="ECS",
                severity=Severity.HIGH,
                title="ECS Service Assigns Public IP to Tasks",
                resource_arn=svc_arn,
                region=self.region,
                description=(
                    f"ECS service '{svc_name}' is configured to assign public IP "
                    f"addresses to tasks. This exposes containers directly to the "
                    f"internet."
                ),
                recommendation=(
                    "Disable public IP assignment and use a load balancer or "
                    "NAT gateway for internet-facing traffic. Set "
                    "'assignPublicIp' to 'DISABLED' in the network configuration."
                ),
            )]
        return []

    def _check_readonly_root_fs(self, td: dict) -> list[Finding]:
        """ECS_005 - Containers without read-only root filesystem."""
        td_arn = td["taskDefinitionArn"]
        writable = []
        for container in td.get("containerDefinitions", []):
            if not container.get("readonlyRootFilesystem", False):
                writable.append(container["name"])

        if writable:
            return [Finding(
                check_id="ECS_005",
                service="ECS",
                severity=Severity.MEDIUM,
                title="ECS Containers Without Read-Only Root Filesystem",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' has containers without a read-only "
                    f"root filesystem: {', '.join(writable)}. A writable root "
                    f"filesystem allows attackers to modify binaries or install malware."
                ),
                recommendation=(
                    "Set 'readonlyRootFilesystem' to true in container definitions. "
                    "Use mounted volumes for paths that require write access."
                ),
            )]
        return []

    def _check_env_secrets(self, td: dict) -> list[Finding]:
        """ECS_006 - Secrets in plain-text environment variables."""
        td_arn = td["taskDefinitionArn"]
        flagged: list[str] = []
        for container in td.get("containerDefinitions", []):
            for env in container.get("environment", []):
                key_upper = env.get("name", "").upper()
                for pattern in SECRET_KEY_PATTERNS:
                    if pattern in key_upper:
                        flagged.append(
                            f"{container['name']}.{env['name']}"
                        )
                        break

        if flagged:
            return [Finding(
                check_id="ECS_006",
                service="ECS",
                severity=Severity.MEDIUM,
                title="ECS Task Definition May Contain Secrets in Environment",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' has potentially sensitive "
                    f"environment variables: {', '.join(flagged)}."
                ),
                recommendation=(
                    "Use the 'secrets' field in container definitions to inject "
                    "sensitive values from AWS Secrets Manager or SSM Parameter "
                    "Store instead of plain-text environment variables."
                ),
            )]
        return []

    def _check_logging(self, td: dict) -> list[Finding]:
        """ECS_007 - Containers without logging configured."""
        td_arn = td["taskDefinitionArn"]
        no_logging = []
        for container in td.get("containerDefinitions", []):
            log_config = container.get("logConfiguration")
            if not log_config or not log_config.get("logDriver"):
                no_logging.append(container["name"])

        if no_logging:
            return [Finding(
                check_id="ECS_007",
                service="ECS",
                severity=Severity.MEDIUM,
                title="ECS Containers Without Logging Configured",
                resource_arn=td_arn,
                region=self.region,
                description=(
                    f"Task definition '{td_arn}' has containers without logging "
                    f"configured: {', '.join(no_logging)}. Without logging, "
                    f"container output is lost and security events cannot be audited."
                ),
                recommendation=(
                    "Configure a log driver (e.g. 'awslogs') in the "
                    "'logConfiguration' of each container definition."
                ),
            )]
        return []

    def _check_container_insights(self, cluster: dict) -> list[Finding]:
        """ECS_008 - ECS cluster without Container Insights enabled."""
        cluster_arn = cluster.get("clusterArn", "unknown")
        cluster_name = cluster.get("clusterName", "unknown")

        settings = cluster.get("settings", [])
        insights_enabled = any(
            s.get("name") == "containerInsights" and s.get("value") == "enabled"
            for s in settings
        )

        if not insights_enabled:
            return [Finding(
                check_id="ECS_008",
                service="ECS",
                severity=Severity.LOW,
                title="ECS Cluster Without Container Insights",
                resource_arn=cluster_arn,
                region=self.region,
                description=(
                    f"ECS cluster '{cluster_name}' does not have Container Insights "
                    f"enabled. Container Insights provides monitoring and "
                    f"troubleshooting data for containerized applications."
                ),
                recommendation=(
                    "Enable Container Insights on the cluster for monitoring "
                    "CPU, memory, disk, and network metrics at the task and "
                    "service level."
                ),
            )]
        return []
