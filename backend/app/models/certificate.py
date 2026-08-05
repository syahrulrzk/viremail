from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    fingerprint = Column(String, unique=True, index=True, nullable=True)
    issuer = Column(JSON, nullable=True)
    subject = Column(JSON, nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    serial_number = Column(String, nullable=True)
    signature_algorithm = Column(String, nullable=True)
    pem = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
