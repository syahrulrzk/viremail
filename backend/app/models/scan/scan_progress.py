from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class ScanProgress(Base):
    """Live progress of a scan job (stage, percent) — used by realtime UIs."""

    __tablename__ = "scan_progress"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    stage = Column(String, nullable=True)      # current stage label
    percent = Column(Integer, default=0)       # 0..100
    message = Column(String, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now())

    job = relationship("ScanJob", back_populates="progress")
