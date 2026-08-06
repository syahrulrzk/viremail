from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from app.db.session import Base


class Worker(Base):
    __tablename__ = "workers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, default="idle")  # idle, busy, offline
    last_heartbeat = Column(DateTime(timezone=True), server_default=func.now())
    tasks_completed = Column(Integer, default=0)
    tasks_failed = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
