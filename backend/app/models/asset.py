from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        index=True,
        nullable=True,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    asset_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    criticality: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    findings: Mapped[list["Finding"]] = relationship(
    back_populates="asset",
    cascade="all, delete-orphan",
)