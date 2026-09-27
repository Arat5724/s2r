import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_public_catalog_and_search(client):
    assert client.get("/health").json()["status"] == "ok"
    assert len(client.get("/api/products").json()["items"]) == 6
    products = client.get("/api/products", params={"q": "노트", "category": "문구"}).json()["items"]
    assert [product["id"] for product in products] == [2]
    assert client.get("/api/products/1").json()["price"] == 89000
    assert client.get("/api/products/999").status_code == 404


@pytest.mark.parametrize("path", ["/api/me", "/api/orders", "/api/orders/1", "/api/admin/orders"])
def test_private_routes_require_login(client, path):
    assert client.get(path).status_code == 401


def test_login_logout_and_no_password_in_response(client, login):
    headers = login()
    response = client.get("/api/me", headers=headers)
    assert response.status_code == 200
    assert set(response.json()) == {"id", "email", "name", "role"}
    assert response.headers["cache-control"] == "no-store"
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/me", headers=headers).status_code == 401


def test_session_expiry(client, login):
    headers = login()
    sessions = client.app.state.sessions
    key = next(iter(sessions._items))
    from app.security import Session
    sessions._items[key] = Session(user_id=1, expires_at=0)
    assert client.get("/api/me", headers=headers).status_code == 401


def test_owner_scope_and_admin_guard(client, login):
    alice = login(0)
    bob = login(1)
    admin = login(2)
    assert {o["user_id"] for o in client.get("/api/orders", headers=alice).json()["items"]} == {1}
    assert {o["user_id"] for o in client.get("/api/orders", headers=bob).json()["items"]} == {2}
    assert client.get("/api/orders/3", headers=alice).status_code == 404
    assert client.get("/api/orders/3", headers=bob).status_code == 200
    assert client.get("/api/admin/orders", headers=alice).status_code == 403
    assert len(client.get("/api/admin/orders", headers=admin).json()["items"]) == 3
    assert client.get("/api/orders/3", headers=admin).status_code == 200


def test_order_lifecycle_and_immutable_decision(client, login):
    member = login(0)
    admin = login(2)
    response = client.post("/api/orders", headers=member, json={"product_id": 1, "quantity": 2, "note": "업무용"})
    assert response.status_code == 201
    order = response.json()
    assert order["user_id"] == 1 and order["status"] == "pending"
    path = f'/api/admin/orders/{order["id"]}/status'
    assert client.patch(path, headers=member, json={"status": "approved"}).status_code == 403
    approved = client.patch(path, headers=admin, json={"status": "approved"})
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert client.post(f'/api/orders/{order["id"]}/cancel', headers=member).status_code == 409
    assert client.patch(path, headers=admin, json={"status": "rejected"}).status_code == 409


def test_cancel_respects_ownership(client, login):
    member = login(0)
    admin = login(2)
    assert client.post("/api/orders/3/cancel", headers=member).status_code == 404
    assert client.post("/api/orders/1/cancel", headers=admin).status_code == 403
    response = client.post("/api/orders/1/cancel", headers=member)
    assert response.status_code == 200 and response.json()["status"] == "cancelled"


@pytest.mark.parametrize("body", [
    {"product_id": 1, "quantity": 0},
    {"product_id": 1, "quantity": 21},
    {"product_id": 1, "quantity": 1, "user_id": 2},
    {"product_id": 1, "quantity": 1, "status": "approved"},
    {"product_id": 1, "quantity": 1, "note": "a" * 301},
    {"product_id": 1, "quantity": 1.5},
])
def test_order_input_constraints(client, login, body):
    assert client.post("/api/orders", headers=login(), json=body).status_code == 422


def test_missing_product_does_not_create_order(client, login):
    headers = login()
    before = client.get("/api/orders", headers=headers).json()
    assert client.post("/api/orders", headers=headers, json={"product_id": 999, "quantity": 1}).status_code == 404
    assert client.get("/api/orders", headers=headers).json() == before


def test_hardening_profile_changes_response_headers(tmp_path):
    for profile in ["baseline", "hardened"]:
        with TestClient(create_app(Settings(data_dir=tmp_path, profile=profile))) as client:
            response = client.get("/")
            assert response.status_code == 200
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert ("content-security-policy" in response.headers) == (profile == "hardened")
            assert ("referrer-policy" in response.headers) == (profile == "hardened")


def test_feature_flag_changes_registered_routes(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        assert client.get("/api/reports/summary").status_code == 404
        assert "/api/reports/summary" not in client.get("/openapi.json").json()["paths"]
    with TestClient(create_app(Settings(data_dir=tmp_path, enable_reports=True))) as client:
        assert client.get("/api/reports/summary").status_code == 401
        accounts = json.loads((tmp_path / "accounts.json").read_text(encoding="utf-8"))
        admin = accounts[2]
        token = client.post("/api/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()["access_token"]
        assert client.get("/api/reports/summary", headers={"Authorization": f"Bearer {token}"}).json() == {"total_orders": 3, "pending_orders": 2}


def test_audit_omits_credentials_query_and_body(client, login, credentials):
    headers = login()
    client.get("/api/products", params={"q": "private-search-marker"})
    client.post("/api/orders", headers=headers, json={"product_id": 2, "quantity": 1, "note": "private-note-marker"})
    log = (client.app.state.db.data_dir / "access.jsonl").read_text(encoding="utf-8")
    assert "private-search-marker" not in log and "private-note-marker" not in log
    assert credentials[0]["password"] not in log
    assert headers["Authorization"].split()[1] not in log
    entries = [json.loads(line) for line in log.splitlines()]
    assert all(len(entry["request_id"]) == 32 for entry in entries)


def test_read_only_requests_preserve_business_state(client, login):
    headers = login()
    before = client.get("/api/orders", headers=headers).json()
    for path in ["/", "/health", "/api/meta", "/api/products", "/api/me", "/api/orders/1"]:
        assert client.get(path, headers=headers).status_code == 200
    assert client.get("/api/orders", headers=headers).json() == before


def test_ui_assets_and_schema(client):
    assert "TeamShelf" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == "teamshelf-1.0.0"
    assert "security" in schema["paths"]["/api/admin/orders"]["get"]


def test_rejects_unconfigured_host(client):
    assert client.get("/", headers={"Host": "unconfigured.test"}).status_code == 400


def test_persistent_data_and_new_session_store(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        accounts_before = (tmp_path / "accounts.json").read_text(encoding="utf-8")
        account = json.loads(accounts_before)[0]
        token = client.post("/api/auth/login", json={"email": account["email"], "password": account["password"]}).json()["access_token"]
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        assert (tmp_path / "accounts.json").read_text(encoding="utf-8") == accounts_before
        assert len(client.get("/api/products").json()["items"]) == 6
        assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
