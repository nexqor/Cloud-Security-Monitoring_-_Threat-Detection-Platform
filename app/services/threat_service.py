"""Runs every detection rule against a fresh resource inventory + CloudTrail events."""
from app.detection import root_login, public_bucket, open_security_group, iam_admin, access_key


def run_detection(inventory: dict, cloudtrail_events: list[dict]) -> list[dict]:
    """
    inventory: output of aws_service.get_resource_inventory()
    cloudtrail_events: output of aws_service.get_recent_cloudtrail_events()
    Returns a flat list of finding dicts (see detection/*.py for shape).
    """
    findings = []

    for event in cloudtrail_events:
        finding = root_login.check(event)
        if finding:
            findings.append(finding)

    for bucket in inventory.get("s3_buckets", []):
        finding = public_bucket.check(bucket)
        if finding:
            findings.append(finding)

    for sg in inventory.get("security_groups", []):
        finding = open_security_group.check(sg)
        if finding:
            findings.append(finding)

    for user in inventory.get("iam_users", []):
        admin_finding = iam_admin.check(user)
        if admin_finding:
            findings.append(admin_finding)

        key_finding = access_key.check(user)
        if key_finding:
            findings.append(key_finding)

    return findings
