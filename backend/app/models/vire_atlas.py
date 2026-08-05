from sqlalchemy import Column, Integer, String, DateTime, JSON, UniqueConstraint
from sqlalchemy.sql import func
from app.db.session import Base


class VireAtlas(Base):
    """VIRE Atlas — cache of completed scan results keyed by (domain, scan_mode).

    Serving a cached result avoids a full 1–5 minute re-scan when the same
    domain is searched again. Results stay cached until the user explicitly
    requests a rescan (which overwrites this row).
    """

    __tablename__ = "vire_atlas"
    __table_args__ = (
        UniqueConstraint("domain", "scan_mode", name="uq_vire_atlas_domain_mode"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    scan_mode = Column(String, default="standard", nullable=False)  # "standard" | "deep"
    result = Column(JSON, nullable=False)  # full scan result payload
    emails_found = Column(Integer, default=0)
    status = Column(String, default="completed")
    hits = Column(Integer, default=0)  # number of times this cached row was served
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    scanned_at = Column(DateTime(timezone=True), nullable=True)  # when the data was actually scanned
