from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class Technology(Base):
    __tablename__ = "technologies"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    name = Column(String, nullable=False)
    category = Column(String, nullable=True)  # CMS, Framework, Server, etc.
    version = Column(String, nullable=True)
    confidence = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
