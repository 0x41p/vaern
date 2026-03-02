import logging

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners import BaseScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class APIGatewayScanner(BaseScanner):
    service_name = "APIGateway"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_rest_apis())
        findings.extend(self._scan_http_apis())
        return findings

    # ------------------------------------------------------------------ #
    # REST APIs (v1)
    # ------------------------------------------------------------------ #

    def _scan_rest_apis(self) -> list[Finding]:
        findings: list[Finding] = []
        try:
            apigw = self._get_client("apigateway")
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    findings.extend(self._check_rest_api(apigw, api))
        except ClientError as e:
            logger.warning("get_rest_apis failed in %s: %s", self.region, e)
        return findings

    def _check_rest_api(self, apigw, api: dict) -> list[Finding]:
        findings: list[Finding] = []
        api_id = api["id"]
        api_name = api.get("name", api_id)
        endpoint_type = api.get("endpointConfiguration", {}).get("types", ["EDGE"])[0]

        # PRIVATE APIs are only reachable via VPC endpoint — not internet-facing
        if endpoint_type == "PRIVATE":
            return []

        api_arn = f"arn:aws:apigateway:{self.region}::/restapis/{api_id}"

        # --- APIGW_001: no authentication ---
        try:
            authorizers = apigw.get_authorizers(RestApiId=api_id).get("items", [])
        except ClientError:
            authorizers = []

        # A resource policy (api["policy"]) can restrict access without authorizers
        has_resource_policy = bool(api.get("policy"))

        if not authorizers and not has_resource_policy:
            findings.append(Finding(
                check_id="APIGW_001",
                service="APIGateway",
                severity=Severity.HIGH,
                title="API Gateway REST API Has No Authentication",
                resource_arn=api_arn,
                region=self.region,
                description=(
                    f"REST API '{api_name}' ({api_id}) is publicly accessible "
                    f"({endpoint_type} endpoint) with no authorizers defined "
                    f"and no resource policy restricting access. "
                    f"Any request to the execute-api URL will be processed "
                    f"without identity verification."
                ),
                recommendation=(
                    "Add an authorizer (JWT/Cognito, Lambda, or IAM) to require "
                    "authentication. Alternatively, add a resource policy that "
                    "restricts access to specific IPs, VPCs, or AWS accounts. "
                    "Consider also disabling the default execute-api endpoint if "
                    "a custom domain is in use."
                ),
            ))

        # --- APIGW_003: access logging per stage ---
        try:
            stages = apigw.get_stages(RestApiId=api_id).get("item", [])
            for stage in stages:
                stage_name = stage.get("stageName", "")
                if not stage.get("accessLogSettings", {}).get("destinationArn"):
                    findings.append(Finding(
                        check_id="APIGW_003",
                        service="APIGateway",
                        severity=Severity.LOW,
                        title="API Gateway Stage Has No Access Logging",
                        resource_arn=f"{api_arn}/stages/{stage_name}",
                        region=self.region,
                        description=(
                            f"REST API '{api_name}' stage '{stage_name}' does not have "
                            f"access logging configured. Without logs, API calls cannot "
                            f"be audited or traced after a security incident."
                        ),
                        recommendation=(
                            "Enable access logging on the stage and direct logs to "
                            "CloudWatch Logs or Kinesis Data Firehose."
                        ),
                    ))
        except ClientError as e:
            logger.warning("get_stages failed for REST API %s: %s", api_id, e)

        return findings

    # ------------------------------------------------------------------ #
    # HTTP APIs (v2)
    # ------------------------------------------------------------------ #

    def _scan_http_apis(self) -> list[Finding]:
        findings: list[Finding] = []
        try:
            apigwv2 = self._get_client("apigatewayv2")
            paginator = apigwv2.get_paginator("get_apis")
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    if api.get("ProtocolType") != "HTTP":
                        continue  # WebSocket APIs have a different auth model
                    findings.extend(self._check_http_api(apigwv2, api))
        except ClientError as e:
            logger.warning("get_apis (v2) failed in %s: %s", self.region, e)
        return findings

    def _check_http_api(self, apigwv2, api: dict) -> list[Finding]:
        findings: list[Finding] = []
        api_id = api["ApiId"]
        api_name = api.get("Name", api_id)
        api_arn = f"arn:aws:apigateway:{self.region}::/apis/{api_id}"

        # --- APIGW_002: unauthenticated routes ---
        try:
            routes = apigwv2.get_routes(ApiId=api_id).get("Items", [])
            open_routes = [
                r.get("RouteKey", "?")
                for r in routes
                if r.get("AuthorizationType", "NONE") == "NONE"
                and not r.get("AuthorizerId")
            ]
            if open_routes:
                routes_str = ", ".join(open_routes[:5])
                if len(open_routes) > 5:
                    routes_str += f" (+{len(open_routes) - 5} more)"
                findings.append(Finding(
                    check_id="APIGW_002",
                    service="APIGateway",
                    severity=Severity.HIGH,
                    title="API Gateway HTTP API Has Unauthenticated Routes",
                    resource_arn=api_arn,
                    region=self.region,
                    description=(
                        f"HTTP API '{api_name}' ({api_id}) has {len(open_routes)} "
                        f"route(s) with no authorizer configured: {routes_str}. "
                        f"Requests matching these routes are processed without any "
                        f"identity verification."
                    ),
                    recommendation=(
                        "Add a JWT authorizer (Cognito or any OIDC provider) or a "
                        "Lambda authorizer. Apply it to the $default route to protect "
                        "all routes by default, then explicitly override for public routes."
                    ),
                ))
        except ClientError as e:
            logger.warning("get_routes failed for HTTP API %s: %s", api_id, e)

        # --- APIGW_003: access logging per stage ---
        try:
            stages = apigwv2.get_stages(ApiId=api_id).get("Items", [])
            for stage in stages:
                stage_name = stage.get("StageName", "")
                if not stage.get("AccessLogSettings", {}).get("DestinationArn"):
                    findings.append(Finding(
                        check_id="APIGW_003",
                        service="APIGateway",
                        severity=Severity.LOW,
                        title="API Gateway Stage Has No Access Logging",
                        resource_arn=f"{api_arn}/stages/{stage_name}",
                        region=self.region,
                        description=(
                            f"HTTP API '{api_name}' stage '{stage_name}' does not have "
                            f"access logging configured. Without logs, API calls cannot "
                            f"be audited or traced after a security incident."
                        ),
                        recommendation=(
                            "Enable access logging on the stage and direct logs to "
                            "CloudWatch Logs."
                        ),
                    ))
        except ClientError as e:
            logger.warning("get_stages failed for HTTP API %s: %s", api_id, e)

        return findings
