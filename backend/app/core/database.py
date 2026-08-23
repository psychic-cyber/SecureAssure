from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.core.config import get_settings


settings = get_settings()


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Provide a database session for a request."""
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def initialize_database() -> None:
    """Create all registered database tables."""
    Base.metadata.create_all(bind=engine)