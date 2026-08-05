from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    dns_records = Column(JSON, nullable=True)
    mx_records = Column(JSON, nullable=True)
    spf = Column(Text, nullable=True)
    dmarc = Column(Text, nullable=True)
    dkim = Column(Text, nullable=True)
    certificate_transparency = Column(JSON, nullable=True)
    tls_certificate = Column(JSON, nullable=True)
    asn = Column(String, nullable=True)
    ip_addresses = Column(JSON, nullable=True)
    security_txt = Column(Text, nullable=True)
    robots_txt = Column(Text, nullable=True)
    sitemap_xml = Column(Text, nullable=True)
    technologies = Column(JSON, nullable=True)
    public_emails = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
