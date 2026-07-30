"""Thin orchestration layer between the API routes and the raw app/aws/* boto3 wrappers."""
from app.aws import ec2, s3, iam, cloudtrail


def get_resource_inventory() -> dict:
    """Pulls a full snapshot of the account's resources. This is the expensive call —
    used by the dashboard summary and as the input to the detection engine."""
    return {
        "ec2_instances": ec2.list_instances(),
        "security_groups": ec2.list_security_groups(),
        "vpcs": ec2.list_vpcs(),
        "s3_buckets": s3.list_buckets(),
        "iam_users": iam.list_users(),
    }


def get_recent_cloudtrail_events(lookback_hours: int = 24) -> list[dict]:
    return cloudtrail.get_recent_events(lookback_hours=lookback_hours)
