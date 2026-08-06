from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class AtlasDocument(Base):
    """Atlas: public document (PDF/DOCX/XLSX/TXT…) harvested from a domain."""

    __tablename__ = "atlas_documents"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    url = Column(String, nullable=False)
    file_type = Column(String, nullable=True)   # pdf, docx, xlsx, txt…
    size_bytes = Column(Integer, nullable=True)
    emails_found = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    domain = relationship("AtlasDomain", back_populates="documents")
