"""
Entry point for the CloudShield detection Lambda.

Triggered by EventBridge (see app/aws/eventbridge.py / terraform/) on CloudTrail
activity matching the watched event names. Runs the lightweight rule set in
detector.py and publishes to SNS on a match — this is the "real-time" path;
the FastAPI /api/dashboard/scan endpoint is the on-demand/periodic path.
"""
from detector import evaluate_cloudtrail_event, notify


def handler(event, context):
    detail = event.get("detail", {})
    finding = evaluate_cloudtrail_event(detail)

    if finding:
        notify(finding)
        return {"statusCode": 200, "body": f"Finding raised: {finding['rule_id']}"}

    return {"statusCode": 200, "body": "No finding"}
