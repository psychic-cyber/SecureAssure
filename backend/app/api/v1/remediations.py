from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.api.v1.schemas.remediation import (
    RemediationCreate,
    RemediationResponse,
    RemediationUpdate,
)
from backend.app.core.database import get_db
from backend.app.models import Finding, Remediation


router = APIRouter(
    prefix="/remediations",
    tags=["Remediation"],
)


VALID_STATUSES = {
    "OPEN",
    "ASSIGNED",
    "IN_PROGRESS",
    "REMEDIATED",
    "VERIFIED",
    "CLOSED",
}

VALID_PRIORITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


@router.post(
    "",
    response_model=RemediationResponse,
    status_code=201,
)
def create_remediation(
    remediation_data: RemediationCreate,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, remediation_data.finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    if remediation_data.priority not in VALID_PRIORITIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid remediation priority",
        )

    remediation = Remediation(
        finding_id=remediation_data.finding_id,
        recommendation=remediation_data.recommendation,
        assigned_user=remediation_data.assigned_user,
        priority=remediation_data.priority,
        due_date=remediation_data.due_date,
        status="OPEN",
    )

    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    return remediation


@router.get(
    "/{remediation_id}",
    response_model=RemediationResponse,
)
def get_remediation(
    remediation_id: int,
    db: Session = Depends(get_db),
):
    remediation = db.get(Remediation, remediation_id)

    if remediation is None:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    return remediation


@router.get(
    "/finding/{finding_id}",
    response_model=list[RemediationResponse],
)
def get_finding_remediations(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding.remediations


@router.patch(
    "/{remediation_id}",
    response_model=RemediationResponse,
)
def update_remediation(
    remediation_id: int,
    remediation_data: RemediationUpdate,
    db: Session = Depends(get_db),
):
    remediation = db.get(Remediation, remediation_id)

    if remediation is None:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    if (
        remediation_data.priority is not None
        and remediation_data.priority not in VALID_PRIORITIES
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid remediation priority",
        )

    if (
        remediation_data.status is not None
        and remediation_data.status not in VALID_STATUSES
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid remediation status",
        )

    update_data = remediation_data.model_dump(
        exclude_unset=True,
    )

    for field, value in update_data.items():
        setattr(remediation, field, value)

    db.commit()
    db.refresh(remediation)

    return remediation
