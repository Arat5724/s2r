import ast
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TARGET = Path(__file__).resolve().parents[1] / "teamshelf"
EXPECTED = json.loads((Path(__file__).parent / "expected-endpoints.json").read_text(encoding="utf-8"))


def test_manifest_matches_actual_routes(tmp_path):
    for enabled in [False, True]:
        app = create_app(Settings(data_dir=tmp_path, enable_reports=enabled))
        with TestClient(app) as client:
            actual = {(method.upper(), path) for path, operations in client.get("/openapi.json").json()["paths"].items()
                      for method in operations if method in {"get", "post", "patch", "put", "delete", "head", "options"}}
            actual.add(("GET", "/"))
            expected = {(row["method"], row["path"]) for row in EXPECTED["endpoints"] if enabled or "enabled_when" not in row}
            assert actual == expected
            assert len(actual) == (16 if enabled else 15)


def test_manifest_handlers_exist():
    for row in EXPECTED["endpoints"]:
        filename, symbol = row["handler"].split(":")
        tree = ast.parse((TARGET / filename).read_text(encoding="utf-8"))
        assert any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol
                   for node in ast.walk(tree)), row["handler"]


def test_app_keeps_runtime_state_outside_source(tmp_path):
    files = [path for path in TARGET.rglob("*") if path.is_file() and "__pycache__" not in path.parts]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        client.get("/")
        client.get("/api/products")
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    assert before == after
    assert (tmp_path / "teamshelf.sqlite3").exists()
    assert (tmp_path / "access.jsonl").exists()
