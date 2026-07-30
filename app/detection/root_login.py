"""Rule: root account console login -> CRITICAL finding."""
from typing import Optional

RULE_ID = "ROOT_LOGIN"
RISK_POINTS = 40


def check(event: dict) -> Optional[dict]:
    """
    event: one item from app.aws.cloudtrail.get_recent_events()
    Returns a finding dict if the rule fires, else None.
    """
    if event.get("event_name") != "ConsoleLogin":
        return None
    if event.get("username") != "Root":
        return None

    return {
        "rule_id": RULE_ID,
        "title": "Root account console login detected",
        "description": (
            "The AWS root account was used to sign in to the console. Root should "
            "only be used for account-recovery/break-glass scenarios — everyday "
            "administration should go through IAM roles/users with least privilege."
        ),
        "severity": "CRITICAL",
        "risk_points": RISK_POINTS,
        "resource_type": "CloudTrailEvent",
        "resource_id": event.get("event_id"),
        "raw_event": event.get("raw"),
    }
