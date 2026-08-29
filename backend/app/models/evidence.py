from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id"),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    command_or_check: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    observed_value: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    expected_value: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    finding = relationship(
        "Finding",
        back_populates="evidence",
    )