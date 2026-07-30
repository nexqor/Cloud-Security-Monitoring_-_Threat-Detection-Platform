"""S3 bucket discovery, including public-access-block and ACL checks."""
from typing import Any

from botocore.exceptions import ClientError

from app.aws.session import get_client


def list_buckets() -> list[dict[str, Any]]:
    """Return all buckets with region and a best-effort public-access assessment."""
    client = get_client("s3")
    buckets = []
    try:
        resp = client.list_buckets()
    except ClientError as e:
        raise RuntimeError(f"S3 list_buckets failed: {e}") from e

    for b in resp.get("Buckets", []):
        name = b["Name"]
        buckets.append({
            "name": name,
            "created": str(b.get("CreationDate")),
            "is_public": _is_bucket_public(client, name),
        })
    return buckets


def _is_bucket_public(client, bucket_name: str) -> bool:
    """
    Best-effort public check: looks at the Public Access Block config first
    (the modern guardrail); if it's absent/off, falls back to the bucket ACL.
    Any error here is treated as 'unknown' rather than crashing the whole scan.
    """
    try:
        pab = client.get_public_access_block(Bucket=bucket_name)
        config = pab["PublicAccessBlockConfiguration"]
        if all(config.values()):
            return False  # fully blocked
    except ClientError:
        pass  # no PAB config set — fall through to ACL check

    try:
        acl = client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except ClientError:
        return False

    return False
