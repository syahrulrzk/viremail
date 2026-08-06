from sqlalchemy import Column, Integer, String, DateTime, JSON, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasDomain(Base):
    """Atlas: knowledge node for a scanned domain.

    Holds the *normalized current state* of a domain in the knowledge base —
    separate from any single scan. Each scan job appends an AtlasHistory row
    and upserts this node. First/last-seen let the KB track entity lifecycle.
    """

    __tablename__ = "atlas_domains"
    __table_args__ = (
        UniqueConstraint("domain", "scan_mode", name="uq_atlas_domains_domain_mode"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    scan_mode = Column(String, default="standard", nullable=False)  # standard | deep
    status = Column(String, default="completed")  # pending, processing, completed, failed
    confidence_score = Column(Integer, default=0)
    emails_found = Column(Integer, default=0)
    subdomains_found = Column(Integer, default=0)
    security_posture = Column(JSON, nullable=True)  # {mx, spf, dmarc}
    dns_summary = Column(JSON, nullable=True)       # {A: n, MX: n, NS: n, TXT: n}
    hits = Column(Integer, default=0)               # times served from cache
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    emails = relationship("AtlasEmail", back_populates="domain",
                          cascade="all, delete-orphan")
    subdomains = relationship("AtlasSubdomain", back_populates="domain",
                              cascade="all, delete-orphan")
    dns_records = relationship("AtlasDnsRecord", back_populates="domain",
                               cascade="all, delete-orphan")
    certificates = relationship("AtlasCertificate", back_populates="domain",
                                cascade="all, delete-orphan")
    technologies = relationship("AtlasTechnology", back_populates="domain",
                                cascade="all, delete-orphan")
    documents = relationship("AtlasDocument", back_populates="domain",
                             cascade="all, delete-orphan")
    persons = relationship("AtlasPerson", back_populates="domain",
                           cascade="all, delete-orphan")
    histories = relationship("AtlasHistory", back_populates="domain",
                             cascade="all, delete-orphan")
