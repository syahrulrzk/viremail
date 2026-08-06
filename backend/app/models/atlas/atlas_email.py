from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasEmail(Base):
    """Atlas: normalized email knowledge node.

    One row per (domain, email). `smtp_status` and `is_hrd` are refreshed on
    every scan; first/last-seen track lifecycle. `is_hrd` flags recruitment
    mailboxes (hr@, recruitment@, career@…) found on job portals & careers.
    """

    __tablename__ = "atlas_emails"
    __table_args__ = (
        UniqueConstraint("domain_id", "email", name="uq_atlas_emails_domain_email"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    email = Column(String, index=True, nullable=False)
    local_part = Column(String, nullable=True)
    smtp_status = Column(String, default="unchecked")  # ok, rejected, unknown, unchecked
    is_hrd = Column(Boolean, default=False)
    confidence_score = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    domain = relationship("AtlasDomain", back_populates="emails")
    relationships = relationship("AtlasRelationship", back_populates="email",
                                 cascade="all, delete-orphan")
