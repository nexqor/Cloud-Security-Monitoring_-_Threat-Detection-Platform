"""Top-level orchestrator: one call runs a full scan cycle end to end."""
import datetime as dt
import json

from sqlalchemy.orm import Session

from app.models.models import ScanHistory, Finding
from app.services import aws_service, threat_service, alert_service


def run_full_scan(db: Session) -> ScanHistory:
    scan = ScanHistory(started_at=dt.datetime.utcnow(), status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        inventory = aws_service.get_resource_inventory()
        events = aws_service.get_recent_cloudtrail_events()
        findings = threat_service.run_detection(inventory, events)

        resources_scanned = (
            len(inventory["ec2_instances"]) + len(inventory["s3_buckets"])
            + len(inventory["security_groups"]) + len(inventory["iam_users"])
        )

        for f in findings:
            db_finding = Finding(
                scan_id=scan.id,
                rule_id=f["rule_id"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                risk_points=f["risk_points"],
                resource_type=f["resource_type"],
                resource_id=f["resource_id"],
                raw_event=json.dumps(f.get("raw_event")) if f.get("raw_event") else None,
            )
            db.add(db_finding)
            db.flush()  # get db_finding.id before dispatching alerts

            if f["severity"] in ("HIGH", "CRITICAL"):
                alert_service.dispatch_alert(db, db_finding)

        scan.resources_scanned = resources_scanned
        scan.findings_created = len(findings)
        scan.status = "completed"
        scan.finished_at = dt.datetime.utcnow()

    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        scan.finished_at = dt.datetime.utcnow()
        db.commit()
        raise

    db.commit()
    db.refresh(scan)
    return scan
