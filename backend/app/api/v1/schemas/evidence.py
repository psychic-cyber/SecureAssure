from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EvidenceCreate(BaseModel):
    finding_id: int
    source: str
    command_or_check: str | None = None
    observed_value: str | None = None
    expected_value: str | None = None
    evidence_type: str


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    source: str
    command_or_check: str | None
    observed_value: str | None
    expected_value: str | None
    evidence_type: str
    collected_at: datetime
