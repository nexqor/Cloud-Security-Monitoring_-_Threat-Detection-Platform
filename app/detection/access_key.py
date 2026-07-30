"""Rule: active IAM access key older than a threshold -> LOW/MEDIUM finding."""
import datetime as dt
from typing import Optional

RULE_ID = "STALE_ACCESS_KEY"
RISK_POINTS = 15
STALE_DAYS = 90


def check(user: dict) -> Optional[dict]:
    """
    user: one item from app.aws.iam.list_users() (includes nested access_keys).
    Fires once per stale, Active key found for the user.
    """
    for key in user.get("access_keys", []):
        if key.get("status") != "Active":
            continue
        created = key.get("created")
        if not created or created == "None":
            continue
        try:
            created_dt = dt.datetime.fromisoformat(created.split("+")[0])
        except ValueError:
            continue

        age_days = (dt.datetime.utcnow() - created_dt).days
        if age_days >= STALE_DAYS:
            return {
                "rule_id": RULE_ID,
                "title": f"Access key for '{user['username']}' is {age_days} days old",
                "description": (
                    f"Access key {key['access_key_id']} has been active for {age_days} days "
                    f"(threshold: {STALE_DAYS}). Rotate or deactivate keys older than this "
                    "to limit the blast radius of a leaked credential."
                ),
                "severity": "LOW",
                "risk_points": RISK_POINTS,
                "resource_type": "IAM",
                "resource_id": key["access_key_id"],
                "raw_event": None,
            }
    return None
