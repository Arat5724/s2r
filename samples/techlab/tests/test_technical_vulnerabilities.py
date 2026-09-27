"""Regression tests for synthetic catalog routes."""


def test_catalog_and_read_only_sqli_boolean_probe(client):
    regular = client.get("/api/products", params={"q": "no-such-artifact"})
    injected = client.get("/api/products", params={"q": "%' OR 1=1 -- "})
    after = client.get("/api/products")

    assert regular.status_code == injected.status_code == after.status_code == 200
    assert regular.json() == {"items": []}
    assert len(injected.json()["items"]) == 6
    assert {item["id"] for item in injected.json()["items"]} == set(range(1, 7))
    assert injected.json()["items"] == after.json()["items"]


def test_category_filter_is_bypassed_by_sqli(client):
    regular = client.get("/api/products", params={"category": "cli"})
    injected = client.get(
        "/api/products", params={"category": "cli", "q": "%' OR 1=1 -- "},
    )

    assert {item["id"] for item in regular.json()["items"]} == {1, 6}
    assert {item["id"] for item in injected.json()["items"]} == set(range(1, 7))


def test_search_preview_reflects_markup_without_escaping(client):
    markup = '<strong data-techlab-probe="xss">sample</strong>'
    response = client.get("/search/preview", params={"q": markup})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert f'<p id="preview-query">{markup}</p>' in response.text


def test_file_endpoint_crosses_public_boundary_but_not_synthetic_root(client):
    public = client.get("/api/files", params={"name": "guide.txt"})
    private = client.get("/api/files", params={"name": "../private/canary.txt"})
    outside = client.get("/api/files", params={"name": "../../main.py"})

    assert public.status_code == private.status_code == 200
    assert public.headers["content-type"].startswith("text/plain")
    assert "synthetic" in public.text
    assert private.headers["content-type"].startswith("text/plain")
    assert private.text.strip() == "TECHLAB_PRIVATE_CANARY"
    assert outside.status_code == 403


def test_open_redirect_sets_location_without_following_target(client):
    target = "https://example.invalid/s2r-review-probe"
    response = client.get("/go", params={"next": target}, follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == target
    assert response.text == ""


def test_health_and_home(client):
    assert client.get("/health").json() == {"status": "ok", "service": "techlab"}
    home = client.get("/")
    assert home.status_code == 200
    assert "TechLab" in home.text
