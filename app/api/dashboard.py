from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database import get_db
from app.models.models import Finding, ScanHistory
from app.services.monitoring_service import run_full_scan
from app.utils.risk_scoring import calculate_security_score

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_user)])


@router.post("/scan")
def trigger_scan(db: Session = Depends(get_db)):
    """Kicks off a full inventory + CloudTrail + detection scan against the real AWS account."""
    scan = run_full_scan(db)
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "resources_scanned": scan.resources_scanned,
        "findings_created": scan.findings_created,
    }


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    open_findings = db.query(Finding).filter(Finding.status == "open").all()
    score = calculate_security_score([
        {"risk_points": f.risk_points} for f in open_findings
    ])
    last_scan = db.query(ScanHistory).order_by(ScanHistory.started_at.desc()).first()

    return {
        "security_score": score,
        "open_findings": len(open_findings),
        "findings_by_severity": {
            sev: len([f for f in open_findings if f.severity == sev])
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "last_scan": {
            "id": last_scan.id,
            "status": last_scan.status,
            "started_at": last_scan.started_at,
            "finished_at": last_scan.finished_at,
        } if last_scan else None,
    }


@router.get("/timeline")
def attack_timeline(db: Session = Depends(get_db), limit: int = 50):
    findings = db.query(Finding).order_by(Finding.detected_at.desc()).limit(limit).all()
    return [
        {
            "id": f.id, "title": f.title, "severity": f.severity,
            "resource_type": f.resource_type, "resource_id": f.resource_id,
            "detected_at": f.detected_at,
        }
        for f in findings
    ]
