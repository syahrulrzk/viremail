from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from app.db.session import Base


class AtlasUsername(Base):
    """Atlas: username footprint on public platforms (linked to a domain)."""

    __tablename__ = "atlas_usernames"
    __table_args__ = (
        UniqueConstraint("platform", "username", name="uq_atlas_usernames_platform_name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("atlas_domains.id"), nullable=False)
    platform = Column(String, nullable=False)  # github, gitlab, reddit…
    username = Column(String, index=True, nullable=False)
    profile_url = Column(String, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
