import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database import get_db
from app.models.models import Report
from app.services import report_service

router = APIRouter(prefix="/api/reports", tags=["reports"], dependencies=[Depends(get_current_user)])

PERIOD_DAYS = {"daily": 1, "weekly": 7, "monthly": 30}


@router.post("/generate")
def generate_report(report_type: str, fmt: str = "csv", db: Session = Depends(get_db)):
    if report_type not in PERIOD_DAYS:
        raise HTTPException(400, "report_type must be one of: daily, weekly, monthly")
    end = dt.datetime.utcnow()
    start = end - dt.timedelta(days=PERIOD_DAYS[report_type])

    if fmt == "csv":
        report = report_service.generate_csv_report(db, report_type, start, end)
    elif fmt == "pdf":
        report = report_service.generate_pdf_report(db, report_type, start, end)
    else:
        raise HTTPException(400, "fmt must be 'csv' or 'pdf'")

    return {"report_id": report.id, "file_path": report.file_path}


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    return FileResponse(report.file_path, filename=report.file_path.split("/")[-1])


@router.get("/")
def list_reports(db: Session = Depends(get_db)):
    return db.query(Report).order_by(Report.created_at.desc()).all()
