"""SQLAlchemy models."""

import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, sessionmaker, relationship

from config import DATABASE_URL

# Ensure data directory exists for SQLite
os.makedirs(os.path.dirname(DATABASE_URL.replace("sqlite:///", "")), exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Subscription
    tier = Column(String(20), default="free")   # free | monthly | yearly | lifetime
    expires_at = Column(DateTime, nullable=True)

    # Yiban credentials (encrypted at rest)
    yiban_config = Column(Text, nullable=True)  # JSON string, Fernet-encrypted

    # Push
    push_key = Column(String(128), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)

    checkin_logs = relationship("CheckinLog", back_populates="user", order_by="CheckinLog.created_at.desc()")


class CheckinLog(Base):
    __tablename__ = "checkin_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    success = Column(Boolean, nullable=False)
    method = Column(String(20))      # api | ocr | cloud
    message = Column(String(512))    # success message or error reason

    user = relationship("User", back_populates="checkin_logs")


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
