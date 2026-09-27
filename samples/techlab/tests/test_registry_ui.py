"""Check that the registry screen exposes the real local catalog workflows."""

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit


class _Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def with_tag(self, name):
        return [attrs for tag, attrs in self.tags if tag == name]


def _home_elements(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    elements = _Elements()
    elements.feed(response.text)
    return response, elements


def test_home_has_catalog_search_and_category_controls(client):
    response, elements = _home_elements(client)

    assert "TechLab Registry" in response.text
    assert any(attrs.get("lang") == "ko" for attrs in elements.with_tag("html"))
    assert any(attrs.get("role") == "search" for attrs in elements.with_tag("form"))
    assert any(attrs.get("name") == "q" and attrs.get("type") == "search"
               for attrs in elements.with_tag("input"))
    assert any(attrs.get("id") == "package-grid" for attrs in elements.with_tag("div"))

    available_categories = {
        item["category"] for item in client.get("/api/products").json()["items"]
    }
    ui_categories = {
        attrs["data-category"] for attrs in elements.with_tag("button")
        if "data-category" in attrs
    }
    assert available_categories <= ui_categories
    assert "" in ui_categories  # all-categories control


def test_runtime_assets_are_local_and_served(client):
    _, elements = _home_elements(client)
    css = [attrs["href"] for attrs in elements.with_tag("link")
           if "stylesheet" in attrs.get("rel", "").split()]
    scripts = [attrs["src"] for attrs in elements.with_tag("script")
               if "src" in attrs]
    icons = [attrs["href"] for attrs in elements.with_tag("link")
             if "icon" in attrs.get("rel", "").split()]

    assert css and scripts
    for asset in css + scripts + icons:
        parsed = urlsplit(asset)
        assert not parsed.scheme and not parsed.netloc
        assert parsed.path.startswith("/assets/")
        result = client.get(parsed.path)
        assert result.status_code == 200
        assert result.content

    # The screen should start without a remote CDN, font, or imported module.
    for asset in css + scripts:
        source = client.get(asset).text
        assert "@import" not in source
        assert "https://" not in source
        assert "http://" not in source


def test_presented_navigation_reaches_catalog_preview_and_documents(client):
    _, elements = _home_elements(client)
    links = [attrs["href"] for attrs in elements.with_tag("a") if "href" in attrs]
    paths = {urlsplit(link).path for link in links}

    assert {"/api/products", "/search/preview", "/api/files", "/go"} <= paths
    catalog = client.get(next(link for link in links if urlsplit(link).path == "/api/products"))
    assert catalog.status_code == 200
    assert catalog.json()["items"]

    preview_link = next(link for link in links if urlsplit(link).path == "/search/preview")
    preview = client.get(preview_link, params={"q": "sdk"})
    assert preview.status_code == 200
    assert 'id="preview-query"' in preview.text

    documents = [link for link in links if urlsplit(link).path == "/api/files"]
    assert {"guide.txt", "release-notes.txt"} <= {
        parse_qs(urlsplit(link).query).get("name", [None])[0] for link in documents
    }
    for link in documents:
        result = client.get(link)
        assert result.status_code == 200
        assert result.headers["content-type"].startswith("text/plain")
        assert result.text.strip()

    guide_redirect = next(link for link in links if urlsplit(link).path == "/go")
    redirect = client.get(guide_redirect, follow_redirects=False)
    assert redirect.status_code == 307
    assert urlsplit(redirect.headers["location"]).path == "/api/files"
    assert client.get(redirect.headers["location"]).status_code == 200

    # The displayed controls must load the same catalog API that navigation exposes.
    script_urls = [attrs["src"] for attrs in elements.with_tag("script") if "src" in attrs]
    assert any("/api/products" in client.get(url).text for url in script_urls)
