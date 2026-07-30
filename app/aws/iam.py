"""IAM user, access key, and admin-policy discovery."""
from typing import Any

from botocore.exceptions import ClientError

from app.aws.session import get_client


def list_users() -> list[dict[str, Any]]:
    client = get_client("iam")
    users = []
    try:
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                users.append({
                    "username": u["UserName"],
                    "user_id": u["UserId"],
                    "arn": u["Arn"],
                    "created": str(u.get("CreateDate")),
                    "is_admin": _has_admin_policy(client, u["UserName"]),
                    "access_keys": list_access_keys(client, u["UserName"]),
                })
    except ClientError as e:
        raise RuntimeError(f"IAM list_users failed: {e}") from e
    return users


def _has_admin_policy(client, username: str) -> bool:
    try:
        attached = client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        return any("AdministratorAccess" in p["PolicyName"] for p in attached)
    except ClientError:
        return False


def list_access_keys(client, username: str) -> list[dict[str, Any]]:
    try:
        resp = client.list_access_keys(UserName=username)
        return [
            {
                "access_key_id": k["AccessKeyId"],
                "status": k["Status"],
                "created": str(k.get("CreateDate")),
            }
            for k in resp["AccessKeyMetadata"]
        ]
    except ClientError:
        return []
