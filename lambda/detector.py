"""
Standalone detection logic for the Lambda runtime — deliberately dependency-light
(no FastAPI/SQLAlchemy) since Lambda cold starts and packaging favor a small surface.
Mirrors the rules in app/detection/root_login.py; kept in sync manually for now
(see README's "keeping Lambda and the API in sync" note for the tradeoff).
"""
import json
import os
import urllib.request
from typing import Optional


def evaluate_cloudtrail_event(detail: dict) -> Optional[dict]:
    event_name = detail.get("eventName")
    username = detail.get("userIdentity", {}).get("userName") or detail.get("userIdentity", {}).get("type")

    if event_name == "ConsoleLogin" and detail.get("userIdentity", {}).get("type") == "Root":
        return {
            "rule_id": "ROOT_LOGIN",
            "severity": "CRITICAL",
            "title": "Root account console login detected",
            "resource_id": detail.get("eventID"),
        }
    if event_name in ("CreateUser", "AttachUserPolicy", "CreateAccessKey"):
        return {
            "rule_id": f"IAM_{event_name.upper()}",
            "severity": "HIGH",
            "title": f"IAM change: {event_name} by {username}",
            "resource_id": detail.get("eventID"),
        }
    if event_name == "DeleteBucket":
        return {
            "rule_id": "S3_DELETE_BUCKET",
            "severity": "HIGH",
            "title": f"S3 bucket deleted by {username}",
            "resource_id": detail.get("eventID"),
        }
    return None


def notify(finding: dict) -> None:
    """Publishes to SNS if SNS_TOPIC_ARN is set in the Lambda's environment."""
    import boto3

    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        print(f"[lambda] finding (no SNS configured): {finding}")
        return

    client = boto3.client("sns")
    client.publish(
        TopicArn=topic_arn,
        Subject=f"[CloudShield] {finding['severity']} - {finding['title']}"[:100],
        Message=json.dumps(finding),
    )


