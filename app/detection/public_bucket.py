"""Rule: publicly accessible S3 bucket -> MEDIUM finding."""
from typing import Optional

RULE_ID = "PUBLIC_S3_BUCKET"
RISK_POINTS = 20


def check(bucket: dict) -> Optional[dict]:
    """bucket: one item from app.aws.s3.list_buckets()"""
    if not bucket.get("is_public"):
        return None

    return {
        "rule_id": RULE_ID,
        "title": f"S3 bucket '{bucket['name']}' is publicly accessible",
        "description": (
            "This bucket's Public Access Block is off or disabled, or its ACL grants "
            "access to AllUsers/AuthenticatedUsers. Review whether this is intentional "
            "(e.g. static website hosting) or a misconfiguration."
        ),
        "severity": "MEDIUM",
        "risk_points": RISK_POINTS,
        "resource_type": "S3",
        "resource_id": bucket["name"],
        "raw_event": None,
    }
