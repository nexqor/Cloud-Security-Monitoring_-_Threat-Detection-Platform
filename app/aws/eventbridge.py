"""
EventBridge helper — used at setup time (or from Terraform) to wire a rule that
triggers the CloudShield Lambda (lambda/lambda_function.py) off CloudTrail activity.
Not called on the request path; kept here so it lives with the other AWS wrappers.
"""
from botocore.exceptions import ClientError

from app.aws.session import get_client

DEFAULT_RULE_NAME = "cloudshield-security-events"

# Matches the CloudTrail management events CloudShield cares about
DEFAULT_EVENT_PATTERN = {
    "source": ["aws.cloudtrail"],
    "detail": {
        "eventName": [
            "ConsoleLogin", "CreateUser", "DeleteUser",
            "AttachUserPolicy", "CreateAccessKey",
            "StopInstances", "DeleteBucket",
        ]
    },
}


def ensure_rule(lambda_arn: str, rule_name: str = DEFAULT_RULE_NAME) -> str:
    """Create (or update) the EventBridge rule and point it at the detection Lambda."""
    import json

    client = get_client("events")
    try:
        client.put_rule(Name=rule_name, EventPattern=json.dumps(DEFAULT_EVENT_PATTERN), State="ENABLED")
        client.put_targets(Rule=rule_name, Targets=[{"Id": "cloudshield-lambda-target", "Arn": lambda_arn}])
        return rule_name
    except ClientError as e:
        raise RuntimeError(f"EventBridge rule setup failed: {e}") from e
