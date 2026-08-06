from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasDnsRecord(Base):
    """Atlas: one DNS record of a domain (A/AAAA/MX/NS/TXT/…)."""

    __tablename__ = "atlas_dns_records"
    __table_args__ = (
        UniqueConstraint("domain_id", "record_type", "name", "value",
                         name="uq_atlas_dns_domain_type_name_value"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    record_type = Column(String, nullable=False)  # A, AAAA, MX, NS, TXT, CNAME…
    name = Column(String, nullable=True)          # record owner name ("" for apex)
    value = Column(Text, nullable=False)          # rdata as text
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="dns_records")
