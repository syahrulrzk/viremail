from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from app.db.session import Base


class WorkerLog(Base):
    """Audit trail of worker activity (lifecycle events, errors)."""

    __tablename__ = "worker_logs"

    id = Column(Integer, primary_key=True, index=True)
    worker_id = Column(Integer, ForeignKey("workers.id"), nullable=True)
    level = Column(String, default="info")  # info, warning, error
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
