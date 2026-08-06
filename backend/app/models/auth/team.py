from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


# Many-to-many: Team <-> User (a user can sit on several teams, a team has
# several users). `role` lets us tag team-level roles (admin / member).
team_members = Table(
    "team_members",
    Base.metadata,
    Column("team_id", Integer, ForeignKey("teams.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role", String, default="member"),
    Column("joined_at", DateTime(timezone=True), server_default=func.now()),
    UniqueConstraint("team_id", "user_id", name="uq_team_members"),
)


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    organization = relationship("Organization", back_populates="teams")
    members = relationship("User", secondary=team_members, backref="teams")
