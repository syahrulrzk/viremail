from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasCertificate(Base):
    """Atlas: TLS / x509 certificate observed for a domain (CT & TLS analysis)."""

    __tablename__ = "atlas_certificates"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    fingerprint = Column(String, unique=True, index=True, nullable=True)
    issuer = Column(Text, nullable=True)
    subject = Column(Text, nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    serial_number = Column(String, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="certificates")
