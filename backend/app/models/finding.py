from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    service_id: Mapped[int | None] = mapped_column(
        ForeignKey("services.id"),
        nullable=True,
        index=True,
    )

    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id"),
        nullable=True,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    detection_source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    recommendation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    detected_at: Mapped[datetime] = mapped_column(
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

    asset: Mapped["Asset"] = relationship(
        back_populates="findings",
    )

    service: Mapped["Service | None"] = relationship(
        back_populates="findings",
    )

    scan: Mapped["Scan | None"] = relationship(
        back_populates="findings",
    )

    risk_assessment: Mapped["RiskAssessment | None"] = relationship(
    back_populates="finding",
    uselist=False,
    cascade="all, delete-orphan",
)

    security_controls: Mapped[list["SecurityControl"]] = relationship(
    secondary="finding_controls",
    back_populates="findings",
)

    evidence = relationship(
        "Evidence",
        back_populates="finding",
        cascade="all, delete-orphan",
    )

    remediations = relationship(
        "Remediation",
        back_populates="finding",
        cascade="all, delete-orphan",
    )
