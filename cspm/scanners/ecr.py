import json
import logging
import re

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

logger = logging.getLogger(__name__)

INSPECTOR_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.LOW,
    "UNTRIAGED": Severity.MEDIUM,
}

# Matches ECR image URIs:  <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
# or with @sha256:<digest>
ECR_IMAGE_RE = re.compile(
    r"(\d+)\.dkr\.ecr\.([^.]+)\.amazonaws\.com/([^:@]+)(?::([^@]+))?(?:@(.+))?"
)


@register_scanner
class ECRScanner(BaseScanner):
    service_name = "ECR"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        ecr = self._get_client("ecr")

        repos = self._list_repositories(ecr)
        for repo in repos:
            findings.extend(self._check_scan_on_push(repo))
            findings.extend(self._check_image_tag_mutability(repo))
            findings.extend(self._check_lifecycle_policy(ecr, repo))
            findings.extend(self._check_repository_policy(ecr, repo))

        # Vulnerability scanning
        ecs_image_map = self._build_ecs_image_map()
        findings.extend(self._scan_vulnerabilities(ecr, repos, ecs_image_map))

        return findings

    # ------------------------------------------------------------------ #
    # AWS data helpers
    # ------------------------------------------------------------------ #

    def _list_repositories(self, ecr) -> list[dict]:
        repos: list[dict] = []
        paginator = ecr.get_paginator("describe_repositories")
        try:
            for page in paginator.paginate():
                repos.extend(page.get("repositories", []))
        except ClientError as e:
            logger.warning("Failed to list ECR repositories: %s", e)
        return repos

    # ------------------------------------------------------------------ #
    # Posture checks
    # ------------------------------------------------------------------ #

    def _check_scan_on_push(self, repo: dict) -> list[Finding]:
        """ECR_001 - Image scan on push not enabled."""
        scan_config = repo.get("imageScanningConfiguration", {})
        if not scan_config.get("scanOnPush", False):
            return [Finding(
                check_id="ECR_001",
                service="ECR",
                severity=Severity.HIGH,
                title="ECR Repository Scan-on-Push Disabled",
                resource_arn=repo["repositoryArn"],
                region=self.region,
                description=(
                    f"ECR repository '{repo['repositoryName']}' does not have "
                    f"image scanning on push enabled. Vulnerabilities in pushed "
                    f"images will not be automatically detected."
                ),
                recommendation=(
                    "Enable image scanning on push in the repository settings, "
                    "or enable Amazon Inspector for continuous ECR scanning."
                ),
            )]
        return []

    def _check_image_tag_mutability(self, repo: dict) -> list[Finding]:
        """ECR_002 - Mutable image tags allowed."""
        if repo.get("imageTagMutability") != "IMMUTABLE":
            return [Finding(
                check_id="ECR_002",
                service="ECR",
                severity=Severity.MEDIUM,
                title="ECR Repository Allows Mutable Image Tags",
                resource_arn=repo["repositoryArn"],
                region=self.region,
                description=(
                    f"ECR repository '{repo['repositoryName']}' allows mutable "
                    f"image tags. This means tags like 'latest' can be overwritten, "
                    f"making it difficult to ensure image provenance and integrity."
                ),
                recommendation=(
                    "Set image tag mutability to IMMUTABLE to prevent tags from "
                    "being overwritten. Use unique tags (e.g., git SHA) for each "
                    "image build."
                ),
            )]
        return []

    def _check_lifecycle_policy(self, ecr, repo: dict) -> list[Finding]:
        """ECR_003 - No lifecycle policy configured."""
        try:
            ecr.get_lifecycle_policy(repositoryName=repo["repositoryName"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "LifecyclePolicyNotFoundException":
                return [Finding(
                    check_id="ECR_003",
                    service="ECR",
                    severity=Severity.LOW,
                    title="ECR Repository Has No Lifecycle Policy",
                    resource_arn=repo["repositoryArn"],
                    region=self.region,
                    description=(
                        f"ECR repository '{repo['repositoryName']}' has no lifecycle "
                        f"policy. Without a lifecycle policy, old and untagged images "
                        f"accumulate indefinitely, increasing storage costs and attack "
                        f"surface."
                    ),
                    recommendation=(
                        "Create a lifecycle policy to automatically expire old or "
                        "untagged images. For example, keep only the last 10 tagged "
                        "images and expire untagged images after 1 day."
                    ),
                )]
            logger.warning("Failed to check lifecycle policy for %s: %s",
                           repo["repositoryName"], e)
        return []

    def _check_repository_policy(self, ecr, repo: dict) -> list[Finding]:
        """ECR_004 - Repository policy allows public access."""
        try:
            resp = ecr.get_repository_policy(repositoryName=repo["repositoryName"])
            policy = json.loads(resp["policyText"])
            for statement in policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", {})
                if principal == "*" or principal.get("AWS") == "*":
                    return [Finding(
                        check_id="ECR_004",
                        service="ECR",
                        severity=Severity.CRITICAL,
                        title="ECR Repository Policy Allows Public Access",
                        resource_arn=repo["repositoryArn"],
                        region=self.region,
                        description=(
                            f"ECR repository '{repo['repositoryName']}' has a "
                            f"resource policy that grants access to all AWS "
                            f"principals ('*'). This effectively makes the "
                            f"repository public."
                        ),
                        recommendation=(
                            "Restrict the repository policy to specific AWS accounts "
                            "or IAM principals. Remove any statements with "
                            "Principal: '*'."
                        ),
                    )]
        except ClientError as e:
            if e.response["Error"]["Code"] != "RepositoryPolicyNotFoundException":
                logger.warning("Failed to check repository policy for %s: %s",
                               repo["repositoryName"], e)
        return []

    # ------------------------------------------------------------------ #
    # Vulnerability scanning
    # ------------------------------------------------------------------ #

    def _scan_vulnerabilities(
        self,
        ecr,
        repos: list[dict],
        ecs_image_map: dict[str, list[str]],
    ) -> list[Finding]:
        """Try Inspector v2 first, fall back to ECR basic scan."""
        findings = self._try_inspector_scan(ecs_image_map)
        if findings is not None:
            return findings

        # Fallback to ECR basic scan
        logger.warning(
            "Inspector v2 unavailable, falling back to ECR basic scan. "
            "Exploitability data (EPSS, exploit status) will not be available."
        )
        return self._ecr_basic_scan(ecr, repos, ecs_image_map)

    def _try_inspector_scan(
        self, ecs_image_map: dict[str, list[str]]
    ) -> list[Finding] | None:
        """Query Inspector v2 for ECR container image vulnerabilities.

        Returns None if Inspector is not available, otherwise returns findings list.
        """
        try:
            inspector = self._get_client("inspector2")
            findings: list[Finding] = []
            paginator = inspector.get_paginator("list_findings")

            filter_criteria = {
                "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
                "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            }

            for page in paginator.paginate(filterCriteria=filter_criteria):
                for f in page.get("findings", []):
                    finding = self._parse_inspector_finding(f, ecs_image_map)
                    if finding:
                        findings.append(finding)

            return findings
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                return None
            raise

    def _parse_inspector_finding(
        self, f: dict, ecs_image_map: dict[str, list[str]]
    ) -> Finding | None:
        """Parse a single Inspector v2 finding into our Finding model."""
        vuln = f.get("packageVulnerabilityDetails", {})
        cve_id = vuln.get("vulnerabilityId", "")
        if not cve_id:
            return None

        # Severity
        severity_str = f.get("severity", "MEDIUM")
        severity = INSPECTOR_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Scores
        cvss_score = None
        inspector_score = f.get("inspectorScore")
        if inspector_score is not None:
            cvss_score = float(inspector_score)
        elif vuln.get("cvss"):
            # Use first available CVSS score
            for score_entry in vuln["cvss"]:
                if "baseScore" in score_entry:
                    cvss_score = float(score_entry["baseScore"])
                    break

        epss_score = None
        epss_detail = f.get("epss")
        if epss_detail and "score" in epss_detail:
            epss_score = float(epss_detail["score"])

        exploit_available = None
        exploit_detail = f.get("exploitAvailable")
        if exploit_detail is not None:
            exploit_available = exploit_detail == "YES"

        fix_available = None
        fix_detail = f.get("fixAvailable")
        if fix_detail is not None:
            fix_available = fix_detail == "YES"

        # Package info
        package_name = None
        package_version = None
        fixed_in_version = None
        vulnerable_packages = vuln.get("vulnerablePackages", [])
        if vulnerable_packages:
            pkg = vulnerable_packages[0]
            package_name = pkg.get("name")
            package_version = pkg.get("version")
            fixed_in_version = pkg.get("fixedInVersion")

        # Resource info
        resources = f.get("resources", [])
        resource_arn = resources[0]["id"] if resources else "unknown"
        repo_name = ""
        if resources:
            details = resources[0].get("details", {})
            ecr_image = details.get("awsEcrContainerImage", {})
            repo_name = ecr_image.get("repositoryName", "")

        # ECS context
        ecs_context = self._match_ecs_context(repo_name, ecs_image_map)

        # Dynamic check ID
        check_id = "ECR_V" + cve_id.replace("CVE-", "").replace("-", "_")

        description = f"{cve_id} found in {repo_name or resource_arn}"
        if package_name:
            description += f" (package: {package_name}"
            if package_version:
                description += f" {package_version}"
            description += ")"
        if ecs_context:
            description += f". Running in ECS: {ecs_context}"

        recommendation = f"Upgrade {package_name or 'affected package'}"
        if fixed_in_version:
            recommendation += f" to {fixed_in_version}"
        recommendation += ". "
        if exploit_available:
            recommendation += "PRIORITY: Known exploit exists. "
        if epss_score and epss_score > 0.5:
            recommendation += f"High exploitation probability (EPSS: {epss_score:.1%}). "

        return Finding(
            check_id=check_id,
            service="ECR",
            severity=severity,
            title=f"{cve_id} in {repo_name or 'ECR image'}",
            resource_arn=resource_arn,
            region=self.region,
            description=description,
            recommendation=recommendation.rstrip(),
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            exploit_available=exploit_available,
            fix_available=fix_available,
            package_name=package_name,
            package_version=package_version,
            fixed_in_version=fixed_in_version,
        )

    def _ecr_basic_scan(
        self,
        ecr,
        repos: list[dict],
        ecs_image_map: dict[str, list[str]],
    ) -> list[Finding]:
        """Fallback: use ECR basic scan findings per repo/image."""
        findings: list[Finding] = []

        for repo in repos:
            repo_name = repo["repositoryName"]
            repo_arn = repo["repositoryArn"]
            try:
                images = self._list_images(ecr, repo_name)
            except ClientError:
                continue

            for image in images:
                image_id = {}
                if "imageDigest" in image:
                    image_id["imageDigest"] = image["imageDigest"]
                elif "imageTag" in image:
                    image_id["imageTag"] = image["imageTag"]
                else:
                    continue

                try:
                    paginator = ecr.get_paginator("describe_image_scan_findings")
                    for page in paginator.paginate(
                        repositoryName=repo_name, imageId=image_id
                    ):
                        for vuln in page.get("imageScanFindings", {}).get("findings", []):
                            finding = self._parse_basic_scan_finding(
                                vuln, repo_name, repo_arn, ecs_image_map
                            )
                            if finding:
                                findings.append(finding)
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code == "ScanNotFoundException":
                        continue
                    logger.warning(
                        "Failed to get scan findings for %s: %s", repo_name, e
                    )

        return findings

    def _list_images(self, ecr, repo_name: str) -> list[dict]:
        images: list[dict] = []
        paginator = ecr.get_paginator("list_images")
        for page in paginator.paginate(repositoryName=repo_name):
            images.extend(page.get("imageIds", []))
        return images

    def _parse_basic_scan_finding(
        self,
        vuln: dict,
        repo_name: str,
        repo_arn: str,
        ecs_image_map: dict[str, list[str]],
    ) -> Finding | None:
        """Parse a single ECR basic scan finding."""
        cve_id = vuln.get("name", "")
        if not cve_id:
            return None

        severity_str = vuln.get("severity", "MEDIUM").upper()
        severity = INSPECTOR_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Basic scan has limited package info in attributes
        package_name = None
        package_version = None
        for attr in vuln.get("attributes", []):
            if attr.get("key") == "package_name":
                package_name = attr.get("value")
            elif attr.get("key") == "package_version":
                package_version = attr.get("value")

        ecs_context = self._match_ecs_context(repo_name, ecs_image_map)

        check_id = "ECR_V" + cve_id.replace("CVE-", "").replace("-", "_")

        description = f"{cve_id} found in {repo_name}"
        if package_name:
            description += f" (package: {package_name}"
            if package_version:
                description += f" {package_version}"
            description += ")"
        if ecs_context:
            description += f". Running in ECS: {ecs_context}"

        recommendation = f"Upgrade {package_name or 'affected package'} to a patched version."

        return Finding(
            check_id=check_id,
            service="ECR",
            severity=severity,
            title=f"{cve_id} in {repo_name}",
            resource_arn=repo_arn,
            region=self.region,
            description=description,
            recommendation=recommendation,
            cve_id=cve_id,
            package_name=package_name,
            package_version=package_version,
        )

    # ------------------------------------------------------------------ #
    # ECS-to-image tracing
    # ------------------------------------------------------------------ #

    def _build_ecs_image_map(self) -> dict[str, list[str]]:
        """Map image URIs to ECS services that use them.

        Returns dict[repo_name, list[context_str]] where context_str is like
        "cluster/prod -> service/api".
        """
        image_map: dict[str, list[str]] = {}
        try:
            ecs = self._get_client("ecs")
            cluster_arns = self._list_ecs_clusters(ecs)

            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.rsplit("/", 1)[-1]
                service_arns = self._list_ecs_services(ecs, cluster_arn)
                if not service_arns:
                    continue

                services = self._describe_ecs_services(ecs, cluster_arn, service_arns)
                for svc in services:
                    svc_name = svc.get("serviceName", "unknown")
                    td_arn = svc.get("taskDefinition", "")
                    if not td_arn:
                        continue

                    try:
                        resp = ecs.describe_task_definition(taskDefinition=td_arn)
                        td = resp["taskDefinition"]
                    except ClientError:
                        continue

                    for container in td.get("containerDefinitions", []):
                        image_uri = container.get("image", "")
                        match = ECR_IMAGE_RE.match(image_uri)
                        if match:
                            repo_name = match.group(3)
                            context = f"cluster/{cluster_name} \u2192 service/{svc_name}"
                            image_map.setdefault(repo_name, []).append(context)
        except Exception as e:
            logger.warning("Failed to build ECS image map: %s", e)

        return image_map

    def _list_ecs_clusters(self, ecs) -> list[str]:
        arns: list[str] = []
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            arns.extend(page.get("clusterArns", []))
        return arns

    def _list_ecs_services(self, ecs, cluster_arn: str) -> list[str]:
        arns: list[str] = []
        paginator = ecs.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster_arn):
            arns.extend(page.get("serviceArns", []))
        return arns

    def _describe_ecs_services(
        self, ecs, cluster_arn: str, service_arns: list[str]
    ) -> list[dict]:
        services: list[dict] = []
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            resp = ecs.describe_services(cluster=cluster_arn, services=batch)
            services.extend(resp.get("services", []))
        return services

    def _match_ecs_context(
        self, repo_name: str, ecs_image_map: dict[str, list[str]]
    ) -> str:
        """Return ECS context string for a repo, or empty string."""
        contexts = ecs_image_map.get(repo_name, [])
        if not contexts:
            return ""
        return "; ".join(contexts)
