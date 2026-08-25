from datetime import datetime

from sqlalchemy import DateTime, String, Table, Column, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


finding_controls = Table(
    "finding_controls",
    Base.metadata,
    Column(
        "finding_id",
        ForeignKey("findings.id"),
        primary_key=True,
    ),
    Column(
        "control_id",
        ForeignKey("security_controls.id"),
        primary_key=True,
    ),
)


class SecurityControl(Base):
    __tablename__ = "security_controls"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    control_code: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    framework: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    implementation_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
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
        secondary=finding_controls,
        back_populates="security_controls",
    )