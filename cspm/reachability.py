"""
Shared network reachability helpers.

build_route_table_data() does a single paginated describe_route_tables call
and returns three dicts that callers combine to answer:
  "does this subnet route to an Internet Gateway?"

Usage:
    subnet_to_rt, vpc_main_rt, rt_has_igw = build_route_table_data(ec2)
    routable = is_subnet_internet_routable(subnet_id, vpc_id,
                                           subnet_to_rt, vpc_main_rt, rt_has_igw)
"""

import logging

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def build_route_table_data(
    ec2,
) -> tuple[dict[str, str], dict[str, str], dict[str, bool]]:
    """Return (subnet_to_rt, vpc_main_rt, rt_has_igw).

    subnet_to_rt  – subnet_id  → route_table_id  (explicit association only)
    vpc_main_rt   – vpc_id     → route_table_id  (main/default RT for the VPC)
    rt_has_igw    – route_table_id → True if it has a 0.0.0.0/0 or ::/0 route
                                     whose target is an Internet Gateway (igw-*)
    """
    subnet_to_rt: dict[str, str] = {}
    vpc_main_rt: dict[str, str] = {}
    rt_has_igw: dict[str, bool] = {}

    try:
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page.get("RouteTables", []):
                rt_id = rt["RouteTableId"]
                vpc_id = rt.get("VpcId", "")

                has_igw = any(
                    (
                        route.get("DestinationCidrBlock") == "0.0.0.0/0"
                        or route.get("DestinationIpv6CidrBlock") == "::/0"
                    )
                    and route.get("GatewayId", "").startswith("igw-")
                    and route.get("State") == "active"
                    for route in rt.get("Routes", [])
                )
                rt_has_igw[rt_id] = has_igw

                for assoc in rt.get("Associations", []):
                    if assoc.get("Main") and vpc_id:
                        vpc_main_rt[vpc_id] = rt_id
                    if subnet_id := assoc.get("SubnetId"):
                        subnet_to_rt[subnet_id] = rt_id

    except ClientError as e:
        logger.warning("describe_route_tables failed: %s", e)

    return subnet_to_rt, vpc_main_rt, rt_has_igw


def is_subnet_internet_routable(
    subnet_id: str,
    vpc_id: str,
    subnet_to_rt: dict[str, str],
    vpc_main_rt: dict[str, str],
    rt_has_igw: dict[str, bool],
) -> bool:
    """Return True if the subnet's effective route table routes to an IGW.

    Falls back to the VPC's main route table when there is no explicit
    subnet association. Returns True (conservative / avoids false negatives)
    when neither association can be found.
    """
    rt_id = subnet_to_rt.get(subnet_id) or vpc_main_rt.get(vpc_id)
    if rt_id is None:
        return True  # can't determine — be conservative, keep the finding
    return rt_has_igw.get(rt_id, False)
