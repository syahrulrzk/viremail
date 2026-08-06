from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.db.session import Base


class WorkerQueue(Base):
    """Queue health stats per queue name (celery queues: default, deep…)."""

    __tablename__ = "worker_queues"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    length = Column(Integer, default=0)       # pending items
    processed = Column(Integer, default=0)    # completed since counter reset
    failed = Column(Integer, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now())
