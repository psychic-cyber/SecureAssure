from fastapi import FastAPI

from backend.app.api.v1.health import router as health_router
from backend.app.core.config import get_settings
from backend.app.core.database import initialize_database
from backend.app.models import Asset, Finding, Scan, Service

settings = get_settings()

initialize_database()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Automated Information Security Risk & Assurance Framework",
)

app.include_router(
    health_router,
    prefix=settings.api_v1_prefix,
)


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }