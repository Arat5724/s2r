"""Confirm that the deliberately vulnerable local XSS fixture is reachable."""

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_search_preview_reflects_markup_in_html(tmp_path):
    marker = '<strong id="xss-training-probe">probe</strong>'

    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        response = client.get("/search/preview", params={"q": marker})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert f'<p id="preview-query">{marker}</p>' in response.text
