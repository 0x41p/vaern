import json

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

DEPRECATED_RUNTIMES = {
    "python2.7",
    "python3.6",
    "python3.7",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "ruby2.5",
    "ruby2.7",
    "java8",
    "go1.x",
}

SECRET_KEY_PATTERNS = ["SECRET", "PASSWORD", "API_KEY", "TOKEN", "PRIVATE_KEY"]


@register_scanner
class LambdaScanner(BaseScanner):
    service_name = "Lambda"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        lambda_client = self._get_client("lambda")
        iam_client = self._get_client("iam")

        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                function_name = func["FunctionName"]
                function_arn = func["FunctionArn"]

                findings.extend(self._check_deprecated_runtime(func, function_arn))
                findings.extend(self._check_public_access_policy(lambda_client, function_name, function_arn))
                findings.extend(self._check_vpc_config(func, function_arn))
                findings.extend(self._check_overly_permissive_role(iam_client, func, function_arn))
                findings.extend(self._check_env_secrets(func, function_arn))

        return findings

    def _check_deprecated_runtime(self, func: dict, function_arn: str) -> list[Finding]:
        runtime = func.get("Runtime", "")
        if runtime in DEPRECATED_RUNTIMES:
            return [Finding(
                check_id="LAM_001",
                service="Lambda",
                severity=Severity.HIGH,
                title="Lambda Function Uses Deprecated Runtime",
                resource_arn=function_arn,
                region=self.region,
                description=(
                    f"Lambda function '{func['FunctionName']}' uses deprecated "
                    f"runtime '{runtime}'. Deprecated runtimes no longer receive "
                    f"security patches and may be blocked from deployment."
                ),
                recommendation="Update the function to use a supported runtime version.",
            )]
        return []

    def _check_public_access_policy(
        self, lambda_client, function_name: str, function_arn: str
    ) -> list[Finding]:
        try:
            resp = lambda_client.get_policy(FunctionName=function_name)
            policy = json.loads(resp["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

        for statement in policy.get("Statement", []):
            principal = statement.get("Principal")
            has_condition = "Condition" in statement

            if has_condition:
                continue

            is_public = False
            if principal == "*":
                is_public = True
            elif isinstance(principal, dict) and principal.get("AWS") == "*":
                is_public = True

            if is_public:
                return [Finding(
                    check_id="LAM_002",
                    service="Lambda",
                    severity=Severity.CRITICAL,
                    title="Lambda Function Has Public Access Policy",
                    resource_arn=function_arn,
                    region=self.region,
                    description=(
                        f"Lambda function '{function_name}' has a resource-based "
                        f"policy that grants public access (Principal: \"*\") "
                        f"without any conditions."
                    ),
                    recommendation=(
                        "Restrict the function policy to specific AWS accounts, "
                        "services, or ARNs. Add conditions if broad access is required."
                    ),
                )]
        return []

    def _check_vpc_config(self, func: dict, function_arn: str) -> list[Finding]:
        vpc_config = func.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])

        if not vpc_config or not subnet_ids:
            return [Finding(
                check_id="LAM_003",
                service="Lambda",
                severity=Severity.MEDIUM,
                title="Lambda Function Not in VPC",
                resource_arn=function_arn,
                region=self.region,
                description=(
                    f"Lambda function '{func['FunctionName']}' is not configured "
                    f"to run within a VPC. Functions outside a VPC cannot access "
                    f"private resources and lack network-level isolation."
                ),
                recommendation=(
                    "Configure the function to run within a VPC by specifying "
                    "subnets and security groups."
                ),
            )]
        return []

    def _check_overly_permissive_role(
        self, iam_client, func: dict, function_arn: str
    ) -> list[Finding]:
        role_arn = func.get("Role", "")
        # Extract role name from ARN: arn:aws:iam::123456789012:role/my-role
        role_name = role_arn.rsplit("/", 1)[-1] if "/" in role_arn else role_arn

        # Check attached managed policies for AdministratorAccess
        try:
            resp = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in resp.get("AttachedPolicies", []):
                if policy.get("PolicyArn") == "arn:aws:iam::aws:policy/AdministratorAccess":
                    return [Finding(
                        check_id="LAM_004",
                        service="Lambda",
                        severity=Severity.HIGH,
                        title="Lambda Function Uses Overly Permissive Role",
                        resource_arn=function_arn,
                        region=self.region,
                        description=(
                            f"Lambda function '{func['FunctionName']}' uses role "
                            f"'{role_name}' which has the AdministratorAccess "
                            f"managed policy attached."
                        ),
                        recommendation=(
                            "Apply the principle of least privilege. Replace "
                            "AdministratorAccess with a policy that grants only "
                            "the permissions the function requires."
                        ),
                    )]
        except ClientError:
            return []

        # Check inline policies for Action "*" with Resource "*"
        try:
            inline_resp = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_resp.get("PolicyNames", []):
                policy_resp = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                policy_doc = policy_resp.get("PolicyDocument", {})
                # PolicyDocument may already be a dict or may be URL-encoded JSON
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)

                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    actions = statement.get("Action", [])
                    resources = statement.get("Resource", [])

                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if "*" in actions and "*" in resources:
                        return [Finding(
                            check_id="LAM_004",
                            service="Lambda",
                            severity=Severity.HIGH,
                            title="Lambda Function Uses Overly Permissive Role",
                            resource_arn=function_arn,
                            region=self.region,
                            description=(
                                f"Lambda function '{func['FunctionName']}' uses role "
                                f"'{role_name}' which has an inline policy "
                                f"'{policy_name}' granting Action \"*\" on "
                                f"Resource \"*\"."
                            ),
                            recommendation=(
                                "Apply the principle of least privilege. Replace "
                                "the wildcard action and resource with specific "
                                "permissions the function requires."
                            ),
                        )]
        except ClientError:
            pass

        return []

    def _check_env_secrets(self, func: dict, function_arn: str) -> list[Finding]:
        env_vars = func.get("Environment", {}).get("Variables", {})
        if not env_vars:
            return []

        suspicious_keys = []
        for key in env_vars:
            key_upper = key.upper()
            for pattern in SECRET_KEY_PATTERNS:
                if pattern in key_upper:
                    suspicious_keys.append(key)
                    break

        if suspicious_keys:
            key_list = ", ".join(suspicious_keys)
            return [Finding(
                check_id="LAM_005",
                service="Lambda",
                severity=Severity.MEDIUM,
                title="Lambda Function Environment Variables May Contain Secrets",
                resource_arn=function_arn,
                region=self.region,
                description=(
                    f"Lambda function '{func['FunctionName']}' has environment "
                    f"variables with potentially sensitive key names: {key_list}."
                ),
                recommendation=(
                    "Store sensitive values in AWS Secrets Manager or "
                    "SSM Parameter Store (SecureString) instead of plain-text "
                    "environment variables."
                ),
            )]
        return []
