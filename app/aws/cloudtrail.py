"""CloudTrail event lookup — the security-relevant event names from the architecture doc."""
import datetime as dt
from typing import Any

from botocore.exceptions import ClientError

from app.aws.session import get_client

# Events the detection engine cares about (see app/detection/)
WATCHED_EVENT_NAMES = [
    "ConsoleLogin",
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "CreateAccessKey",
    "StopInstances",
    "DeleteBucket",
]


def get_recent_events(lookback_hours: int = 24) -> list[dict[str, Any]]:
    """Pull recent CloudTrail events across the watched event names."""
    client = get_client("cloudtrail")
    start_time = dt.datetime.utcnow() - dt.timedelta(hours=lookback_hours)
    events = []

    for event_name in WATCHED_EVENT_NAMES:
        try:
            paginator = client.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
                EndTime=dt.datetime.utcnow(),
            ):
                for e in page["Events"]:
                    events.append({
                        "event_name": e.get("EventName"),
                        "event_time": str(e.get("EventTime")),
                        "username": e.get("Username"),
                        "event_id": e.get("EventId"),
                        "resources": [r.get("ResourceName") for r in e.get("Resources", [])],
                        "raw": e.get("CloudTrailEvent"),
                    })
        except ClientError as e:
            # A single event-type lookup failing (e.g. permissions) shouldn't kill the whole pull
            events.append({"event_name": event_name, "error": str(e)})

    return events
