from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasPerson(Base):
    """Atlas: person linked to a domain (from git histories, mailing lists,
    team pages, job portal postings…)."""

    __tablename__ = "atlas_persons"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, nullable=True)           # hr, dev, founder…
    email_id = Column(Integer, ForeignKey("atlas_emails.id"), nullable=True)
    source_name = Column(String, nullable=True)    # github, mailing_list, website…
    context = Column(String, nullable=True)        # repo / list / page
    url = Column(String, nullable=True)
    is_hrd = Column(Boolean, default=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="persons")
