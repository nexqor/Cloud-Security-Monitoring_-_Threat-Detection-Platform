"""SNS publish wrapper, used by alert_service for the SNS -> email/SMS fan-out."""
from botocore.exceptions import ClientError

from app.aws.session import get_client
from app.config import get_settings

settings = get_settings()


def publish_alert(subject: str, message: str) -> bool:
    if not settings.sns_topic_arn:
        return False
    client = get_client("sns")
    try:
        client.publish(TopicArn=settings.sns_topic_arn, Subject=subject[:100], Message=message)
        return True
    except ClientError:
        return False
