from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.api.v1.schemas.evidence import (
    EvidenceCreate,
    EvidenceResponse,
)
from backend.app.core.database import get_db
from backend.app.models import Evidence, Finding


router = APIRouter(
    prefix="/evidence",
    tags=["Evidence"],
)


@router.post(
    "",
    response_model=EvidenceResponse,
    status_code=201,
)
def create_evidence(
    evidence_data: EvidenceCreate,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, evidence_data.finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    evidence = Evidence(
        finding_id=evidence_data.finding_id,
        source=evidence_data.source,
        command_or_check=evidence_data.command_or_check,
        observed_value=evidence_data.observed_value,
        expected_value=evidence_data.expected_value,
        evidence_type=evidence_data.evidence_type,
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return evidence


@router.get(
    "/{evidence_id}",
    response_model=EvidenceResponse,
)
def get_evidence(
    evidence_id: int,
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found",
        )

    return evidence


@router.get(
    "/finding/{finding_id}",
    response_model=list[EvidenceResponse],
)
def get_finding_evidence(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding.evidence

