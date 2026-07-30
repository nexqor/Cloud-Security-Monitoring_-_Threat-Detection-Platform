import datetime as dt

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class ScanHistory(Base):
    """One row per AWS account scan run (resource inventory + CloudTrail pull)."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=dt.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    aws_region = Column(String(32))
    resources_scanned = Column(Integer, default=0)
    findings_created = Column(Integer, default=0)
    status = Column(String(16), default="running")  # running | completed | failed
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    """A single security finding produced by the detection engine."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_history.id"), nullable=True)

    rule_id = Column(String(64), index=True)          # e.g. "ROOT_LOGIN", "OPEN_SSH"
    title = Column(String(256))
    description = Column(Text)
    severity = Column(String(16))                     # LOW | MEDIUM | HIGH | CRITICAL
    risk_points = Column(Integer, default=0)

    resource_type = Column(String(64))                 # EC2 | S3 | IAM | SecurityGroup | CloudTrailEvent
    resource_id = Column(String(256))                  # instance id, bucket name, arn, etc.
    aws_region = Column(String(32), nullable=True)

    raw_event = Column(Text, nullable=True)             # JSON blob of the underlying event/resource
    status = Column(String(16), default="open")         # open | acknowledged | resolved
    detected_at = Column(DateTime, default=dt.datetime.utcnow)

    scan = relationship("ScanHistory", back_populates="findings")
    alerts = relationship("Alert", back_populates="finding")


class Alert(Base):
    """Record of an alert dispatched for a finding, across one or more channels."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    channel = Column(String(32))       # console | email | sns | dashboard
    sent_at = Column(DateTime, default=dt.datetime.utcnow)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="alerts")


class Report(Base):
    """Generated report metadata (daily/weekly/monthly, PDF/CSV)."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String(16))     # daily | weekly | monthly
    format = Column(String(8))           # pdf | csv
    file_path = Column(String(512))
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
