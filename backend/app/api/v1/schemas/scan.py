from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanCreate(BaseModel):
    target: str
    scan_type: str = "service_detection"
    scanner: str = "nmap"
    timeout: int = 300


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scanner: str
    scan_type: str
    target: str
    status: str
    configuration: str | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
