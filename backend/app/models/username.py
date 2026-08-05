from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.session import Base


class Username(Base):
    __tablename__ = "usernames"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    github = Column(JSON, nullable=True)
    gitlab = Column(JSON, nullable=True)
    reddit = Column(JSON, nullable=True)
    stackoverflow = Column(JSON, nullable=True)
    docker_hub = Column(JSON, nullable=True)
    pypi = Column(JSON, nullable=True)
    npm = Column(JSON, nullable=True)
    medium = Column(JSON, nullable=True)
    gravatar = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
