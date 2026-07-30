"""Rule: IAM user with AdministratorAccess attached -> CRITICAL finding."""
from typing import Optional

RULE_ID = "IAM_ADMIN_USER"
RISK_POINTS = 40


def check(user: dict) -> Optional[dict]:
    """user: one item from app.aws.iam.list_users()"""
    if not user.get("is_admin"):
        return None

    return {
        "rule_id": RULE_ID,
        "title": f"IAM user '{user['username']}' has AdministratorAccess",
        "description": (
            "This user has the AdministratorAccess managed policy attached, granting "
            "full control of the account. Confirm this is intentional and scoped to "
            "as few users as possible — prefer role assumption over standing admin users."
        ),
        "severity": "CRITICAL",
        "risk_points": RISK_POINTS,
        "resource_type": "IAM",
        "resource_id": user["arn"],
        "raw_event": None,
    }
