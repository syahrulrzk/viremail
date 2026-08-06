from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasSubdomain(Base):
    """Atlas: discovered subdomain of a domain."""

    __tablename__ = "atlas_subdomains"
    __table_args__ = (
        UniqueConstraint("domain_id", "subdomain", name="uq_atlas_subdomains_domain_sub"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    subdomain = Column(String, index=True, nullable=False)
    resolved_ip = Column(String, nullable=True)
    crawled = Column(Boolean, default=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="subdomains")
