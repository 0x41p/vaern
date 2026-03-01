from __future__ import annotations

import csv
import io
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Lock

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cspm.models import Severity
from cspm.scanners import RETRY_CONFIG

logger = logging.getLogger(__name__)

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@dataclass
class ToxicCombination:
    id: str           # "TC-1", "TC-2" — for future ack support
    title: str
    severity: Severity
    description: str
    recommendation: str
    path: list[str]   # human-readable chain steps
    resource_arn: str
    region: str


class SecurityGraph:
    def __init__(self, session: boto3.Session, regions: list[str]) -> None:
        self._session = session
        self._regions = regions
        self._iam = session.client("iam", config=RETRY_CONFIG)
        self._role_admin_cache: dict[str, bool] = {}
        self._role_admin_lock = Lock()

    def build(self) -> list[ToxicCombination]:
        combos: list[ToxicCombination] = []

        # TC-1: internet-exposed compute + IAM role, run per-region in parallel
        max_workers = min(len(self._regions) * 3, 20)
        with ThreadPoolExecutor(max_workers=max(max_workers, 1)) as executor:
            futures = []
            for region in self._regions:
                futures.append(executor.submit(self._tc1_ec2, region))
                futures.append(executor.submit(self._tc1_lambda, region))
                futures.append(executor.submit(self._tc1_ecs, region))
            for future in as_completed(futures):
                try:
                    combos.extend(future.result())
                except Exception as e:
                    logger.warning("TC-1 sub-check failed: %s", e)

        # TC-2: IAM console user + admin + no MFA (global, run once)
        try:
            combos.extend(self._tc2_iam_admin_no_mfa())
        except Exception as e:
            logger.warning("TC-2 check failed: %s", e)

        sev_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        combos.sort(key=lambda c: sev_order.get(c.severity, 99))
        return combos

    # ------------------------------------------------------------------ #
    # TC-1: Internet-Exposed Compute + IAM Role
    # ------------------------------------------------------------------ #

    def _tc1_ec2(self, region: str) -> list[ToxicCombination]:
        combos: list[ToxicCombination] = []
        try:
            ec2 = self._session.client("ec2", region_name=region, config=RETRY_CONFIG)

            instances: list[dict] = []
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ):
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("PublicIpAddress") and inst.get("IamInstanceProfile"):
                            instances.append(inst)

            if not instances:
                return []

            all_sg_ids = list({
                sg["GroupId"]
                for inst in instances
                for sg in inst.get("SecurityGroups", [])
            })
            sg_ports_map = _build_sg_open_ports_map(ec2, all_sg_ids)

            for inst in instances:
                inst_id = inst["InstanceId"]
                public_ip = inst.get("PublicIpAddress", "")
                sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]

                open_ports: list[str] = []
                seen_ports: set[str] = set()
                for sg_id in sg_ids:
                    for p in sg_ports_map.get(sg_id, []):
                        if p not in seen_ports:
                            open_ports.append(p)
                            seen_ports.add(p)

                if not open_ports:
                    continue

                profile_arn = inst["IamInstanceProfile"].get("Arn", "")
                profile_name = profile_arn.rsplit("/", 1)[-1] if "/" in profile_arn else profile_arn
                if not profile_name:
                    continue

                role_arn = self._resolve_instance_profile_role(profile_name)
                if not role_arn:
                    continue

                is_admin = self._is_role_admin(role_arn)
                severity = Severity.CRITICAL if is_admin else Severity.HIGH
                ports_str = ", ".join(open_ports)
                role_label = f"{role_arn} [AdministratorAccess]" if is_admin else role_arn
                owner_id = inst.get("OwnerId", "")
                inst_arn = f"arn:aws:ec2:{region}:{owner_id}:instance/{inst_id}"

                combos.append(ToxicCombination(
                    id="TC-1",
                    title=(
                        "Internet-Exposed EC2 Instance with Admin IAM Role"
                        if is_admin else
                        "Internet-Exposed EC2 Instance with IAM Role"
                    ),
                    severity=severity,
                    description=(
                        f"EC2 instance {inst_id} in {region} has a public IP ({public_ip}) "
                        f"with security group rules open to 0.0.0.0/0 on {ports_str}, "
                        f"and is assigned IAM role {role_arn}."
                        + (
                            " This role has AdministratorAccess — a single exploit gives full account control."
                            if is_admin else
                            " The attached IAM role may provide a lateral movement stepping stone."
                        )
                    ),
                    recommendation=(
                        "Remove AdministratorAccess from the role and apply least-privilege. "
                        "Restrict security group ingress to known IP ranges or remove the public IP."
                        if is_admin else
                        "Restrict security group ingress to known IP ranges or remove the public IP. "
                        "Audit the IAM role permissions and apply least-privilege."
                    ),
                    path=[
                        f"Internet (0.0.0.0/0 — {ports_str})",
                        f"{inst_id} (EC2, {region}, public IP {public_ip})",
                        role_label,
                    ],
                    resource_arn=inst_arn,
                    region=region,
                ))
        except ClientError as e:
            logger.warning("TC-1 EC2 check failed in %s: %s", region, e)
        return combos

    def _tc1_lambda(self, region: str) -> list[ToxicCombination]:
        combos: list[ToxicCombination] = []
        try:
            lam = self._session.client("lambda", region_name=region, config=RETRY_CONFIG)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    func_arn = func["FunctionArn"]
                    func_name = func["FunctionName"]
                    role_arn = func.get("Role", "")
                    if not role_arn:
                        continue

                    if not self._is_lambda_public(lam, func_name):
                        continue

                    is_admin = self._is_role_admin(role_arn)
                    severity = Severity.CRITICAL if is_admin else Severity.HIGH
                    role_label = f"{role_arn} [AdministratorAccess]" if is_admin else role_arn

                    combos.append(ToxicCombination(
                        id="TC-1",
                        title=(
                            "Internet-Exposed Lambda Function with Admin IAM Role"
                            if is_admin else
                            "Internet-Exposed Lambda Function with IAM Role"
                        ),
                        severity=severity,
                        description=(
                            f"Lambda function '{func_name}' in {region} is publicly invokable "
                            f"(function URL with AuthType NONE or resource-based policy Principal \"*\"), "
                            f"and its execution role is {role_arn}."
                            + (
                                " This role has AdministratorAccess — a single exploit gives full account control."
                                if is_admin else
                                " The execution role may provide lateral movement opportunities."
                            )
                        ),
                        recommendation=(
                            "Remove AdministratorAccess from the execution role and apply least-privilege. "
                            "Require authentication on the function URL or restrict the resource policy."
                            if is_admin else
                            "Require authentication on the function URL or restrict the resource policy. "
                            "Audit the execution role permissions and apply least-privilege."
                        ),
                        path=[
                            "Internet (public function URL or open resource policy)",
                            f"{func_name} (Lambda, {region})",
                            role_label,
                        ],
                        resource_arn=func_arn,
                        region=region,
                    ))
        except ClientError as e:
            logger.warning("TC-1 Lambda check failed in %s: %s", region, e)
        return combos

    def _tc1_ecs(self, region: str) -> list[ToxicCombination]:
        combos: list[ToxicCombination] = []
        try:
            ecs = self._session.client("ecs", region_name=region, config=RETRY_CONFIG)
            ec2 = self._session.client("ec2", region_name=region, config=RETRY_CONFIG)

            cluster_arns: list[str] = []
            for page in ecs.get_paginator("list_clusters").paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            if not cluster_arns:
                return []

            tasks: list[dict] = []
            for cluster_arn in cluster_arns:
                task_arns: list[str] = []
                for page in ecs.get_paginator("list_tasks").paginate(
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
                        logger.warning("describe_tasks failed: %s", e)

            if not tasks:
                return []

            # Collect ENI IDs, map them back to their tasks
            eni_to_task: dict[str, dict] = {}
            for task in tasks:
                eni_id = _task_eni_id(task)
                if eni_id:
                    eni_to_task[eni_id] = task

            if not eni_to_task:
                return []

            # Bulk describe ENIs to find which have public IPs
            eni_public_map: dict[str, str] = {}  # eni_id → public IP
            eni_ids = list(eni_to_task.keys())
            for i in range(0, len(eni_ids), 200):
                batch = eni_ids[i : i + 200]
                try:
                    resp = ec2.describe_network_interfaces(NetworkInterfaceIds=batch)
                    for eni in resp.get("NetworkInterfaces", []):
                        pub_ip = eni.get("Association", {}).get("PublicIp")
                        if pub_ip:
                            eni_public_map[eni["NetworkInterfaceId"]] = pub_ip
                except ClientError as e:
                    logger.warning("describe_network_interfaces failed: %s", e)

            # Cache task definition ARN → taskRoleArn
            task_def_cache: dict[str, str] = {}

            for eni_id, task in eni_to_task.items():
                if eni_id not in eni_public_map:
                    continue

                public_ip = eni_public_map[eni_id]
                task_def_arn = task.get("taskDefinitionArn", "")

                if task_def_arn not in task_def_cache:
                    try:
                        td_resp = ecs.describe_task_definition(taskDefinition=task_def_arn)
                        task_def_cache[task_def_arn] = (
                            td_resp.get("taskDefinition", {}).get("taskRoleArn", "")
                        )
                    except ClientError:
                        task_def_cache[task_def_arn] = ""

                role_arn = task_def_cache[task_def_arn]
                if not role_arn:
                    continue

                is_admin = self._is_role_admin(role_arn)
                severity = Severity.CRITICAL if is_admin else Severity.HIGH
                role_label = f"{role_arn} [AdministratorAccess]" if is_admin else role_arn
                task_arn = task.get("taskArn", "unknown")
                cluster_name = task.get("clusterArn", "").rsplit("/", 1)[-1]
                task_short = task_arn.rsplit("/", 1)[-1]

                combos.append(ToxicCombination(
                    id="TC-1",
                    title=(
                        "Internet-Exposed ECS Fargate Task with Admin IAM Role"
                        if is_admin else
                        "Internet-Exposed ECS Fargate Task with IAM Role"
                    ),
                    severity=severity,
                    description=(
                        f"ECS Fargate task in cluster '{cluster_name}' ({region}) has a public IP "
                        f"({public_ip}) and task IAM role {role_arn}."
                        + (
                            " This role has AdministratorAccess — a single exploit gives full account control."
                            if is_admin else
                            " The task IAM role may provide lateral movement opportunities."
                        )
                    ),
                    recommendation=(
                        "Remove AdministratorAccess from the task role and apply least-privilege. "
                        "Disable public IP assignment or move the task behind a load balancer."
                        if is_admin else
                        "Disable public IP assignment or move the task behind a load balancer. "
                        "Audit the task IAM role permissions and apply least-privilege."
                    ),
                    path=[
                        f"Internet (public IP {public_ip})",
                        f"{task_short} (ECS Fargate, {region}, cluster {cluster_name})",
                        role_label,
                    ],
                    resource_arn=task_arn,
                    region=region,
                ))
        except ClientError as e:
            logger.warning("TC-1 ECS check failed in %s: %s", region, e)
        return combos

    # ------------------------------------------------------------------ #
    # TC-2: IAM Console User + Admin Access + No MFA
    # ------------------------------------------------------------------ #

    def _tc2_iam_admin_no_mfa(self) -> list[ToxicCombination]:
        combos: list[ToxicCombination] = []
        try:
            cred_report = self._get_credential_report()
        except Exception as e:
            logger.warning("Could not fetch IAM credential report for TC-2: %s", e)
            return []

        for row in cred_report:
            username = row.get("user", "")
            if username == "<root_account>":
                continue
            if row.get("password_enabled", "false").lower() != "true":
                continue
            if row.get("mfa_active", "false").lower() == "true":
                continue

            user_arn = row.get("arn", f"arn:aws:iam::unknown:user/{username}")
            admin_label = self._user_admin_label(username)
            if not admin_label:
                continue

            combos.append(ToxicCombination(
                id="TC-2",
                title="IAM Console User with Admin Access and No MFA",
                severity=Severity.CRITICAL,
                description=(
                    f"IAM user '{username}' has console access, no MFA configured, "
                    f"and administrator-level permissions ({admin_label}). "
                    f"If this account is phished or the password is compromised, "
                    f"an attacker gains immediate full control of the AWS account."
                ),
                recommendation=(
                    "Enable MFA for this user immediately. "
                    "If full admin access is required, enforce it via an IAM policy condition "
                    "requiring MFA (aws:MultiFactorAuthPresent). "
                    "If admin access is not required, apply least-privilege."
                ),
                path=[
                    f"{username} (IAM console user, no MFA)",
                    admin_label,
                    "Full AWS account control",
                ],
                resource_arn=user_arn,
                region="global",
            ))
        return combos

    def _user_admin_label(self, username: str) -> str:
        """Return a human-readable label if the user has admin access, else ''."""
        try:
            # Direct managed policies
            resp = self._iam.list_attached_user_policies(UserName=username)
            for policy in resp.get("AttachedPolicies", []):
                if policy.get("PolicyArn") == ADMIN_POLICY_ARN:
                    return "AdministratorAccess (direct managed policy)"

            # Direct inline policies
            inline_resp = self._iam.list_user_policies(UserName=username)
            for policy_name in inline_resp.get("PolicyNames", []):
                policy_resp = self._iam.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )
                doc = policy_resp.get("PolicyDocument", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
                for stmt in _iter_statements(doc):
                    if _is_admin_statement(stmt):
                        return f"Action:* Resource:* (inline policy '{policy_name}')"

            # Group membership
            groups_resp = self._iam.list_groups_for_user(UserName=username)
            for group in groups_resp.get("Groups", []):
                group_name = group["GroupName"]

                grp_managed = self._iam.list_attached_group_policies(GroupName=group_name)
                for policy in grp_managed.get("AttachedPolicies", []):
                    if policy.get("PolicyArn") == ADMIN_POLICY_ARN:
                        return f"AdministratorAccess (via group '{group_name}')"

                grp_inline = self._iam.list_group_policies(GroupName=group_name)
                for policy_name in grp_inline.get("PolicyNames", []):
                    grp_policy = self._iam.get_group_policy(
                        GroupName=group_name, PolicyName=policy_name
                    )
                    doc = grp_policy.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in _iter_statements(doc):
                        if _is_admin_statement(stmt):
                            return (
                                f"Action:* Resource:* "
                                f"(group '{group_name}', inline policy '{policy_name}')"
                            )
        except ClientError as e:
            logger.warning("Could not check admin access for user %s: %s", username, e)
        return ""

    def _get_credential_report(self) -> list[dict]:
        for _ in range(10):
            try:
                resp = self._iam.generate_credential_report()
                if resp["State"] == "COMPLETE":
                    break
            except ClientError:
                pass
            time.sleep(2)
        resp = self._iam.get_credential_report()
        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    # ------------------------------------------------------------------ #
    # IAM role admin detection — cached, thread-safe
    # ------------------------------------------------------------------ #

    def _is_role_admin(self, role_arn: str) -> bool:
        with self._role_admin_lock:
            if role_arn in self._role_admin_cache:
                return self._role_admin_cache[role_arn]

        role_name = role_arn.rsplit("/", 1)[-1]
        result = False
        try:
            resp = self._iam.list_attached_role_policies(RoleName=role_name)
            for policy in resp.get("AttachedPolicies", []):
                if policy.get("PolicyArn") == ADMIN_POLICY_ARN:
                    result = True
                    break

            if not result:
                inline_resp = self._iam.list_role_policies(RoleName=role_name)
                for policy_name in inline_resp.get("PolicyNames", []):
                    policy_resp = self._iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )
                    doc = policy_resp.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in _iter_statements(doc):
                        if _is_admin_statement(stmt):
                            result = True
                            break
                    if result:
                        break
        except ClientError as e:
            logger.warning("Could not check admin status for role %s: %s", role_arn, e)

        with self._role_admin_lock:
            self._role_admin_cache[role_arn] = result
        return result

    def _resolve_instance_profile_role(self, profile_name: str) -> str:
        """Resolve an EC2 instance profile name to its IAM role ARN."""
        try:
            resp = self._iam.get_instance_profile(InstanceProfileName=profile_name)
            roles = resp.get("InstanceProfile", {}).get("Roles", [])
            if roles:
                return roles[0].get("Arn", "")
        except ClientError as e:
            logger.warning("Could not resolve instance profile %s: %s", profile_name, e)
        return ""

    def _is_lambda_public(self, lam, func_name: str) -> bool:
        """Return True if the Lambda function is publicly invokable."""
        # Check function URL config
        try:
            url_resp = lam.get_function_url_config(FunctionName=func_name)
            if url_resp.get("AuthType") == "NONE":
                return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.warning("get_function_url_config failed for %s: %s", func_name, e)

        # Check resource-based policy
        try:
            policy_resp = lam.get_policy(FunctionName=func_name)
            policy = json.loads(policy_resp["Policy"])
            for stmt in policy.get("Statement", []):
                if "Condition" in stmt:
                    continue
                principal = stmt.get("Principal")
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.warning("get_policy failed for %s: %s", func_name, e)

        return False


# ------------------------------------------------------------------ #
# Module-level helpers
# ------------------------------------------------------------------ #

def _build_sg_open_ports_map(ec2, sg_ids: list[str]) -> dict[str, list[str]]:
    """Return sg_id → list of port descriptions open to the internet."""
    if not sg_ids:
        return {}
    result: dict[str, list[str]] = {}
    for i in range(0, len(sg_ids), 200):
        batch = sg_ids[i : i + 200]
        try:
            resp = ec2.describe_security_groups(GroupIds=batch)
            for sg in resp.get("SecurityGroups", []):
                ports: list[str] = []
                for rule in sg.get("IpPermissions", []):
                    ports.extend(_rule_exposed_ports(rule))
                if ports:
                    result[sg["GroupId"]] = ports
        except ClientError as e:
            logger.warning("describe_security_groups failed: %s", e)
    return result


def _rule_exposed_ports(rule: dict) -> list[str]:
    """Return port descriptions for rules open to 0.0.0.0/0 or ::/0."""
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
    return [
        f"{label} {from_port}" if from_port == to_port
        else f"{label} {from_port}-{to_port}"
    ]


def _task_eni_id(task: dict) -> str | None:
    """Extract ENI ID from an ECS task's attachments."""
    for attachment in task.get("attachments", []):
        if attachment.get("type") == "ElasticNetworkInterface":
            for detail in attachment.get("details", []):
                if detail.get("name") == "networkInterfaceId":
                    return detail.get("value")
    return None


def _iter_statements(policy_doc: dict) -> list[dict]:
    """Iterate over policy statements, handling both list and single-dict forms."""
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return stmts


def _is_admin_statement(stmt: dict) -> bool:
    """Return True if a policy statement grants Action:* on Resource:* with Effect:Allow."""
    if stmt.get("Effect") != "Allow":
        return False
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources
