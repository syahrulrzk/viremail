from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasTechnology(Base):
    """Atlas: technology detected on a domain (Laravel, Nginx, WordPress…)."""

    __tablename__ = "atlas_technologies"
    __table_args__ = (
        UniqueConstraint("domain_id", "name", "version",
                         name="uq_atlas_technologies_domain_name_version"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    name = Column(String, nullable=False)
    category = Column(String, nullable=True)  # CMS, Framework, Server, Language…
    version = Column(String, nullable=True)
    confidence = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="technologies")
