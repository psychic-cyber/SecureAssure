from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    likelihood: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    impact: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    confidentiality: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    integrity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    availability: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    assessment_method: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    assessed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    finding: Mapped["Finding"] = relationship(
        back_populates="risk_assessment",
    )