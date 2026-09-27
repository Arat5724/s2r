"""Test the isolated TechLab fixture without importing the older TeamShelf app."""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(Settings(runtime_dir=tmp_path))) as test_client:
        yield test_client

