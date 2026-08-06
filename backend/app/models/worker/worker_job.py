from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class WorkerJob(Base):
    """A job executed by a worker (e.g. one celery task run)."""

    __tablename__ = "worker_jobs"

    id = Column(Integer, primary_key=True, index=True)
    worker_id = Column(Integer, ForeignKey("workers.id"), nullable=True)
    task_name = Column(String, nullable=False)
    task_id = Column(String, unique=True, index=True, nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
