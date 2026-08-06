from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasHistory(Base):
    """Atlas: append-only snapshot of every completed scan for a domain.

    Keeps the full result payload (JSON) so the knowledge base can show how a
    domain evolved over time. The most recent row per (domain, mode) doubles
    as the cache that fast lookups are served from.
    """

    __tablename__ = "atlas_histories"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    scan_mode = Column(String, default="standard", nullable=False)
    status = Column(String, default="completed")
    result = Column(JSON, nullable=False)   # full scan result payload
    emails_found = Column(Integer, default=0)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="histories")
