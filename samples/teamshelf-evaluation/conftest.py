import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TARGET = Path(__file__).resolve().parents[1] / "teamshelf"
sys.path.insert(0, str(TARGET))

from app.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        yield client


@pytest.fixture
def credentials(client):
    return json.loads((client.app.state.db.data_dir / "accounts.json").read_text(encoding="utf-8"))


@pytest.fixture
def login(client, credentials):
    def login_as(index=0):
        account = credentials[index]
        response = client.post("/api/auth/login", json={"email": account["email"], "password": account["password"]})
        assert response.status_code == 200
        return {"Authorization": "Bearer " + response.json()["access_token"]}
    return login_as
