from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt


def test_login_and_metrics_api_access(client) -> None:
    login_response = client.post(
        "/auth/api/login",
        json={
            "org_id": "dev-org",
            "username": "admin",
            "password": "ChangeMeNow!123",
        },
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert "access_token" in payload
    assert "refresh_token" in payload

    metrics_response = client.get(
        "/v1/metrics",
        params={"org_id": "dev-org", "page": 1, "page_size": 10},
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert metrics_response.status_code == 200


def test_refresh_token_rotation(client) -> None:
    login_response = client.post(
        "/auth/api/login",
        json={
            "org_id": "dev-org",
            "username": "admin",
            "password": "ChangeMeNow!123",
        },
    )
    first = login_response.json()

    refresh_response = client.post(
        "/auth/api/refresh",
        json={"refresh_token": first["refresh_token"]},
    )
    assert refresh_response.status_code == 200
    second = refresh_response.json()
    assert second["refresh_token"] != first["refresh_token"]

    reuse_response = client.post(
        "/auth/api/refresh",
        json={"refresh_token": first["refresh_token"]},
    )
    assert reuse_response.status_code == 401


def test_protected_api_rejects_missing_token(client) -> None:
    response = client.get("/v1/metrics", params={"org_id": "dev-org"})
    assert response.status_code == 401


def test_expired_access_token_rejected(client) -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "1",
            "org_id": "dev-org",
            "username": "admin",
            "role": "admin",
            "type": "access",
            "iss": "test-issuer",
            "aud": "test-audience",
            "iat": int((now - timedelta(minutes=20)).timestamp()),
            "exp": int((now - timedelta(minutes=10)).timestamp()),
        },
        "test-access-secret",
        algorithm="HS256",
    )
    response = client.get(
        "/v1/metrics",
        params={"org_id": "dev-org"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
