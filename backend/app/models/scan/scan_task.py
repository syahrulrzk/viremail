from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class ScanTask(Base):
    """One source-level stage inside a scan job (dns, website, docs, ocr,
    subdomains, whois, search, wayback, github, mailing, jobportal, smtp…)."""

    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    source_name = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, skipped, failed
    detail = Column(Text, nullable=True)        # human-readable result / error
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    job = relationship("ScanJob", back_populates="tasks")
