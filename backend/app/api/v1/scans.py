from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.api.v1.schemas.scan import ScanCreate, ScanResponse
from backend.app.core.database import SessionLocal, get_db
from backend.app.models import Scan
from backend.app.scanners.orchestrator import ScanOrchestrator


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


def run_scan_background(scan_id: int, timeout: int) -> None:
    db = SessionLocal()

    try:
        scan = db.get(Scan, scan_id)

        if scan is None:
            return

        orchestrator = ScanOrchestrator()

        try:
            orchestrator.run_nmap_scan(
                db,
                scan,
                timeout=timeout,
            )
        except Exception:
            # The orchestrator records FAILED state and error details.
            pass

    finally:
        db.close()


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not scan_data.target.strip():
        raise HTTPException(
            status_code=400,
            detail="Target must not be empty",
        )

    if scan_data.timeout <= 0:
        raise HTTPException(
            status_code=400,
            detail="Timeout must be greater than zero",
        )

    if scan_data.scanner.lower() != "nmap":
        raise HTTPException(
            status_code=400,
            detail="Only Nmap scanner is currently supported",
        )

    scan = Scan(
        scanner="nmap",
        scan_type=scan_data.scan_type,
        target=scan_data.target.strip(),
        status="PENDING",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        run_scan_background,
        scan.id,
        scan_data.timeout,
    )

    return scan


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = db.get(Scan, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan

