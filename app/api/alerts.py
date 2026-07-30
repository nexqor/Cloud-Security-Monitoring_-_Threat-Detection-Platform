from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database import get_db
from app.models.models import Finding, Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)])


@router.get("/findings")
def list_findings(db: Session = Depends(get_db), status: Optional[str] = None, severity: Optional[str] = None):
    query = db.query(Finding)
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    return query.order_by(Finding.detected_at.desc()).all()


@router.patch("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, new_status: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if new_status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(400, "status must be one of: open, acknowledged, resolved")
    finding.status = new_status
    db.commit()
    return {"id": finding.id, "status": finding.status}


@router.get("/")
def list_alerts(db: Session = Depends(get_db), limit: int = 100):
    return db.query(Alert).order_by(Alert.sent_at.desc()).limit(limit).all()
