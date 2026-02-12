from __future__ import annotations


def test_docs_disabled_by_default(client) -> None:
    response = client.get("/docs")
    assert response.status_code == 404
