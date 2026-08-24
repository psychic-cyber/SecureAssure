from sqlalchemy import inspect

from backend.app.core.database import engine
from backend.app.models import Asset, Service


def test_assets_table_exists():
    inspector = inspect(engine)

    assert "assets" in inspector.get_table_names()


def test_services_table_exists():
    inspector = inspect(engine)

    assert "services" in inspector.get_table_names()


def test_asset_model_is_registered():
    assert Asset.__tablename__ == "assets"


def test_service_model_is_registered():
    assert Service.__tablename__ == "services"


def test_service_has_asset_foreign_key():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("services")

    assert len(foreign_keys) == 1
    assert foreign_keys[0]["referred_table"] == "assets"
    assert foreign_keys[0]["constrained_columns"] == ["asset_id"]