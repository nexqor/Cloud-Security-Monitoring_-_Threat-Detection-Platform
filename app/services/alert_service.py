"""Multi-channel alert dispatch. Called by monitoring_service for HIGH/CRITICAL findings."""
from typing import Optional

from sqlalchemy.orm import Session

from app.aws import sns
from app.models.models import Alert, Finding


def dispatch_alert(db: Session, finding: Finding) -> None:
    subject = f"[CloudShield] {finding.severity} - {finding.title}"
    message = (
        f"Rule: {finding.rule_id}\n"
        f"Severity: {finding.severity}\n"
        f"Resource: {finding.resource_type} {finding.resource_id}\n\n"
        f"{finding.description}"
    )

    # Console channel — always fires, useful for local dev / logs
    print(f"\n[ALERT] {subject}\n{message}\n")
    _record(db, finding.id, "console", True)

    # SNS channel — no-ops cleanly if SNS_TOPIC_ARN isn't configured
    success = sns.publish_alert(subject, message)
    _record(db, finding.id, "sns", success)

    # Dashboard channel — the finding itself is the dashboard alert (queried via /api/alerts)
    _record(db, finding.id, "dashboard", True)


def _record(db: Session, finding_id: int, channel: str, success: bool, error: Optional[str] = None) -> None:
    db.add(Alert(finding_id=finding_id, channel=channel, success=success, error_message=error))
    db.commit()
