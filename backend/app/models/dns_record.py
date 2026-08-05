from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    record_type = Column(String, nullable=False)  # A, AAAA, MX, NS, TXT, CNAME, etc.
    name = Column(String, nullable=False)
    value = Column(JSON, nullable=True)
    ttl = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
