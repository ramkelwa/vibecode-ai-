"""Shared pytest fixtures: temp SQLite DB and FastAPI TestClient."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

import pytest

# Must be set before app modules import settings.
_tmpdir = tempfile.mkdtemp(prefix="vibeshield-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmpdir}/test.db"
os.environ["SCAN_ALLOW_PRIVATE_TARGETS"] = "true"

from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _create_schema() -> Iterator[None]:
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
