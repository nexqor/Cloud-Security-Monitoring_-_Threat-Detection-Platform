"""Generates CSV/PDF reports over findings for a date range."""
import csv
import datetime as dt
import io
import os

from sqlalchemy.orm import Session

from app.models.models import Finding, Report

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")


def _findings_in_range(db: Session, start: dt.datetime, end: dt.datetime) -> list[Finding]:
    return (
        db.query(Finding)
        .filter(Finding.detected_at >= start, Finding.detected_at <= end)
        .order_by(Finding.detected_at.desc())
        .all()
    )


def generate_csv_report(db: Session, report_type: str, start: dt.datetime, end: dt.datetime) -> Report:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    findings = _findings_in_range(db, start, end)

    filename = f"cloudshield_{report_type}_{end.strftime('%Y%m%d')}.csv"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "rule_id", "title", "severity", "risk_points", "resource_type", "resource_id", "detected_at"])
        for finding in findings:
            writer.writerow([
                finding.id, finding.rule_id, finding.title, finding.severity,
                finding.risk_points, finding.resource_type, finding.resource_id, finding.detected_at,
            ])

    report = Report(report_type=report_type, format="csv", file_path=filepath, period_start=start, period_end=end)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def generate_pdf_report(db: Session, report_type: str, start: dt.datetime, end: dt.datetime) -> Report:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    os.makedirs(REPORTS_DIR, exist_ok=True)
    findings = _findings_in_range(db, start, end)

    filename = f"cloudshield_{report_type}_{end.strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    c = canvas.Canvas(filepath, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"CloudShield {report_type.title()} Security Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Period: {start.date()} - {end.date()}  |  Findings: {len(findings)}")
    y -= 30

    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Severity   Rule                     Resource")
    y -= 15
    c.setFont("Helvetica", 9)

    for finding in findings:
        if y < 50:
            c.showPage()
            y = height - 50
        line = f"{finding.severity:<10} {finding.rule_id:<24} {finding.resource_type}:{finding.resource_id}"
        c.drawString(50, y, line[:100])
        y -= 14

    c.save()

    report = Report(report_type=report_type, format="pdf", file_path=filepath, period_start=start, period_end=end)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
