from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RemediationCreate(BaseModel):
    finding_id: int
    recommendation: str
    assigned_user: str | None = None
    priority: str
    due_date: datetime | None = None


class RemediationUpdate(BaseModel):
    assigned_user: str | None = None
    priority: str | None = None
    status: str | None = None
    due_date: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    verification_at: datetime | None = None


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    recommendation: str
    assigned_user: str | None
    priority: str
    status: str
    due_date: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    verification_at: datetime | None
    created_at: datetime
    updated_at: datetime
