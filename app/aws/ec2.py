"""EC2 + Security Group discovery."""
from typing import Any

from botocore.exceptions import ClientError

from app.aws.session import get_client


def list_instances() -> list[dict[str, Any]]:
    """Return a flat list of EC2 instances with the fields the dashboard/detectors need."""
    client = get_client("ec2")
    instances = []
    try:
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    name = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        None,
                    )
                    instances.append({
                        "instance_id": inst["InstanceId"],
                        "name": name,
                        "state": inst["State"]["Name"],
                        "instance_type": inst.get("InstanceType"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                        "launch_time": str(inst.get("LaunchTime")),
                    })
    except ClientError as e:
        raise RuntimeError(f"EC2 describe_instances failed: {e}") from e
    return instances


def list_security_groups() -> list[dict[str, Any]]:
    """Return security groups with their ingress rules, flattened for the detection engine."""
    client = get_client("ec2")
    groups = []
    try:
        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                ingress_rules = []
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        ingress_rules.append({
                            "protocol": perm.get("IpProtocol"),
                            "from_port": perm.get("FromPort"),
                            "to_port": perm.get("ToPort"),
                            "cidr": ip_range.get("CidrIp"),
                        })
                groups.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "vpc_id": sg.get("VpcId"),
                    "ingress_rules": ingress_rules,
                })
    except ClientError as e:
        raise RuntimeError(f"EC2 describe_security_groups failed: {e}") from e
    return groups


def list_vpcs() -> list[dict[str, Any]]:
    client = get_client("ec2")
    try:
        resp = client.describe_vpcs()
        return [
            {"vpc_id": v["VpcId"], "cidr_block": v.get("CidrBlock"), "is_default": v.get("IsDefault", False)}
            for v in resp["Vpcs"]
        ]
    except ClientError as e:
        raise RuntimeError(f"EC2 describe_vpcs failed: {e}") from e
