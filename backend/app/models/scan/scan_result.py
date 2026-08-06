from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class ScanResult(Base):
    """Raw per-entity findings of one scan job (what THIS scan observed).
    Normalized, deduplicated knowledge lives in the atlas tables instead."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    entity_type = Column(String, nullable=False)  # email, subdomain, dns, document, person…
    entity_value = Column(String, nullable=False)
    source_name = Column(String, nullable=True)   # website, mailto, github, jobportal…
    confidence = Column(Integer, nullable=True)
    meta = Column(JSON, nullable=True)            # extra context (url, smtp status…)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
