from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.db.session import Base


class AtlasSource(Base):
    """Atlas: a data source instance that produced knowledge (website, mailto,
    github, jobportal, wayback…). Relationships link emails to sources.

    Seeded from the connector registry (`Source`) on first use.
    """

    __tablename__ = "atlas_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    label = Column(String, nullable=True)      # human label: "Job Portal"
    kind = Column(String, default="observed")  # observed | pattern | tool
    created_at = Column(DateTime(timezone=True), server_default=func.now())
