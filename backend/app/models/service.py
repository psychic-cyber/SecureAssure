from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    protocol: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )

    service_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    service_version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    asset: Mapped["Asset"] = relationship(
        back_populates="services",
    )

    findings: Mapped[list["Finding"]] = relationship(
    back_populates="service",
)