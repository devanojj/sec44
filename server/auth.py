from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from server.config import ServerConfig
from server.db import ServerDatabase
from server.schemas import Principal

ACCESS_COOKIE = "em_access"
REFRESH_COOKIE = "em_refresh"
CSRF_COOKIE = "em_csrf"


class AuthManager:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.hasher = PasswordHasher()

    def hash_password(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        try:
            return bool(self.hasher.verify(hashed, password))
        except Exception:
            return False

    def _encode(self, payload: dict[str, Any], secret: str, ttl_seconds: int) -> str:
        now = datetime.now(UTC)
        claims = {
            **payload,
            "iss": self.config.jwt_issuer,
            "aud": self.config.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        return jwt.encode(claims, secret, algorithm="HS256")

    def create_access_token(self, principal: Principal) -> str:
        payload = {
            "sub": str(principal.user_id),
            "org_id": principal.org_id,
            "username": principal.username,
            "role": principal.role,
            "type": "access",
        }
        return self._encode(payload, self.config.jwt_access_secret, self.config.access_token_ttl_seconds)

    def create_refresh_token(self, principal: Principal, token_id: str) -> str:
        payload = {
            "sub": str(principal.user_id),
            "org_id": principal.org_id,
            "username": principal.username,
            "role": principal.role,
            "type": "refresh",
            "jti": token_id,
        }
        return self._encode(payload, self.config.jwt_refresh_secret, self.config.refresh_token_ttl_seconds)

    def decode_access(self, token: str) -> Principal:
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_access_secret,
                algorithms=["HS256"],
                issuer=self.config.jwt_issuer,
                audience=self.config.jwt_audience,
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid access token") from exc

        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token type")

        role = str(payload.get("role") or "")
        if role not in {"admin", "read_only"}:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid role")

        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid subject claim") from exc

        return Principal(
            user_id=user_id,
            org_id=str(payload.get("org_id")),
            username=str(payload.get("username")),
            role=role,
        )

    def decode_refresh(self, token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_refresh_secret,
                algorithms=["HS256"],
                issuer=self.config.jwt_issuer,
                audience=self.config.jwt_audience,
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token") from exc

        if payload.get("type") != "refresh" or not payload.get("jti"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token type")
        return payload

    def refresh_expiry(self) -> datetime:
        return datetime.now(UTC) + timedelta(seconds=self.config.refresh_token_ttl_seconds)


bearer_scheme = HTTPBearer(auto_error=False)


def issue_csrf_token(secret: str, user_hint: str) -> str:
    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    body = f"{user_hint}:{nonce}:{ts}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{nonce}.{ts}.{mac}"


def verify_csrf_token(secret: str, user_hint: str, token: str, max_age_seconds: int = 7200) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    nonce, ts_text, mac = parts
    if not nonce or not ts_text or not mac:
        return False
    try:
        ts = int(ts_text)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_age_seconds:
        return False
    expected_body = f"{user_hint}:{nonce}:{ts_text}".encode("utf-8")
    expected_mac = hmac.new(secret.encode("utf-8"), expected_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected_mac)


def principal_from_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Principal:
    auth: AuthManager = request.app.state.auth
    token: str | None = None
    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    if not token:
        token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing auth token")
    return auth.decode_access(token)


def require_role(allowed: set[str]):
    def _dep(principal: Principal = Depends(principal_from_request)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return principal

    return _dep


def authenticate_user(db: ServerDatabase, auth: AuthManager, org_id: str, username: str, password: str) -> Principal:
    user = db.get_user(org_id=org_id, username=username)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    if not auth.verify_password(password=password, hashed=user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    db.touch_user_login(user.id)
    return Principal(user_id=user.id, org_id=user.org_id, username=user.username, role=user.role)
