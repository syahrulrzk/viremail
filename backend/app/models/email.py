from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    domain = Column(String, index=True, nullable=False)
    is_valid_format = Column(Boolean, default=True)
    mx_record = Column(JSON, nullable=True)
    spf = Column(Text, nullable=True)
    dmarc = Column(Text, nullable=True)
    dkim = Column(Text, nullable=True)
    gravatar = Column(JSON, nullable=True)
    domain_info = Column(JSON, nullable=True)
    public_references = Column(JSON, nullable=True)
    confidence_score = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
