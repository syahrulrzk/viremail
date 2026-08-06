from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasRelationship(Base):
    """Atlas: knowledge-graph edge.

    example.com --discovered--> hr@example.com --found_in--> Job Portal (98%)

    Each edge ties an email to the source that revealed it, with a confidence
    score and the exact URL. This is what powers graph visualization and
    source-aware queries (e.g. "all emails from GitHub").
    """

    __tablename__ = "atlas_relationships"
    __table_args__ = (
        UniqueConstraint("email_id", "source_id", "url",
                         name="uq_atlas_relationships_email_source_url"),
    )

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("atlas_emails.id"), nullable=False)
    source_id = Column(Integer, ForeignKey("atlas_sources.id"), nullable=False)
    url = Column(String, nullable=True)
    confidence = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    email = relationship("AtlasEmail", back_populates="relationships")
    source = relationship("AtlasSource")
