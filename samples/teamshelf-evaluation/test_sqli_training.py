def test_search_sqli_bypasses_product_category_with_read_only_payload(client):
    regular = client.get("/api/products", params={"q": "", "category": "문구"})
    assert regular.status_code == 200
    assert {item["id"] for item in regular.json()["items"]} == {2, 6}

    injected = client.get(
        "/api/products",
        params={"q": "%' OR 1=1 -- ", "category": "문구"},
    )
    assert injected.status_code == 200
    assert {item["id"] for item in injected.json()["items"]} == set(range(1, 7))

    # The read-only demonstration changes the result set, not the sample records.
    assert {item["id"] for item in client.get("/api/products").json()["items"]} == set(range(1, 7))
