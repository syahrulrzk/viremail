from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from app.db.session import Base


class Source(Base):
    """Connector registry — every data source the engine can use.

    This is the *definition* of a connector (website, github, wayback, docs,
    ocr, jobportal, smtp, …). Which source actually discovered a given email
    is tracked in `atlas_sources` / `atlas_relationships`.
    """

    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)  # website, github…
    type = Column(String, nullable=False)  # crawl, api, search, dns, smtp, subprocess
    description = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
