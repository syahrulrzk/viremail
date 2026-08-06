from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class ScanJob(Base):
    """An execution of a Scan — one Scan may spawn several jobs over time
    (standard vs deep mode, re-scans, scheduled scans)."""

    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    mode = Column(String, default="standard")  # standard | deep | quick | smart
    celery_task_id = Column(String, unique=True, index=True, nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="jobs")
    tasks = relationship("ScanTask", back_populates="job", cascade="all, delete-orphan")
    progress = relationship("ScanProgress", back_populates="job",
                            cascade="all, delete-orphan", uselist=False)
