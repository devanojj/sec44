from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from server.auth import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    AuthManager,
    authenticate_user,
    issue_csrf_token,
    principal_from_request,
    verify_csrf_token,
)
from server.schemas import LoginRequest, Principal, RefreshRequest, TokenPair

router = APIRouter(tags=["auth"])


def _set_auth_cookies(response: RedirectResponse | JSONResponse, request: Request, pair: TokenPair) -> None:
    secure = bool(request.app.state.config.enforce_https)
    response.set_cookie(
        ACCESS_COOKIE,
        pair.access_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=pair.expires_in,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh_token,
        httponly=True,
        secure=secure,
        samesite="strict",
        max_age=request.app.state.config.refresh_token_ttl_seconds,
    )


def _clear_auth_cookies(response: RedirectResponse | JSONResponse) -> None:
    response.delete_cookie(ACCESS_COOKIE)
    response.delete_cookie(REFRESH_COOKIE)
    response.delete_cookie(CSRF_COOKIE)


@router.get("/login")
def login_page(request: Request):
    token = issue_csrf_token(request.app.state.config.csrf_secret, user_hint="anonymous")
    response = request.app.state.templates.TemplateResponse(request, "login.html", {"csrf_token": token})
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=False,
        secure=bool(request.app.state.config.enforce_https),
        samesite="strict",
        max_age=7200,
    )
    return response


@router.post("/auth/login")
def login_form(
    request: Request,
    org_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
    if not csrf_cookie or csrf_cookie != csrf_token:
        raise HTTPException(status_code=403, detail="invalid CSRF token")
    if not verify_csrf_token(request.app.state.config.csrf_secret, user_hint="anonymous", token=csrf_token):
        raise HTTPException(status_code=403, detail="expired CSRF token")

    body = LoginRequest(org_id=org_id, username=username, password=password)
    db = request.app.state.db
    auth: AuthManager = request.app.state.auth
    principal = authenticate_user(db=db, auth=auth, org_id=body.org_id, username=body.username, password=body.password)

    refresh_id = secrets.token_urlsafe(24)
    access_token = auth.create_access_token(principal)
    refresh_token = auth.create_refresh_token(principal, token_id=refresh_id)
    db.store_refresh_token(user_id=principal.user_id, token_id=refresh_id, expires_at=auth.refresh_expiry())

    pair = TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=request.app.state.config.access_token_ttl_seconds,
    )
    response = RedirectResponse(url="/overview", status_code=303)
    _set_auth_cookies(response, request, pair)

    new_csrf = issue_csrf_token(request.app.state.config.csrf_secret, user_hint=principal.username)
    response.set_cookie(
        CSRF_COOKIE,
        new_csrf,
        httponly=False,
        secure=bool(request.app.state.config.enforce_https),
        samesite="strict",
        max_age=7200,
    )
    return response


@router.post("/auth/api/login", response_model=TokenPair)
def api_login(payload: LoginRequest, request: Request) -> JSONResponse:
    db = request.app.state.db
    auth: AuthManager = request.app.state.auth
    principal = authenticate_user(db=db, auth=auth, org_id=payload.org_id, username=payload.username, password=payload.password)

    refresh_id = secrets.token_urlsafe(24)
    pair = TokenPair(
        access_token=auth.create_access_token(principal),
        refresh_token=auth.create_refresh_token(principal, token_id=refresh_id),
        expires_in=request.app.state.config.access_token_ttl_seconds,
    )
    db.store_refresh_token(user_id=principal.user_id, token_id=refresh_id, expires_at=auth.refresh_expiry())
    return JSONResponse(content=pair.model_dump(mode="json"))


@router.post("/auth/refresh")
def refresh(request: Request):
    auth: AuthManager = request.app.state.auth
    db = request.app.state.db
    csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not csrf_cookie or csrf_cookie != csrf_header:
        raise HTTPException(status_code=403, detail="invalid CSRF token")

    refresh_token = request.cookies.get(REFRESH_COOKIE, "")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="missing refresh cookie")

    payload = auth.decode_refresh(refresh_token)
    token_id = str(payload.get("jti"))
    user = db.use_refresh_token(token_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="refresh token revoked or expired")

    principal = Principal(user_id=user.id, org_id=user.org_id, username=user.username, role=user.role)
    next_refresh_id = secrets.token_urlsafe(24)
    pair = TokenPair(
        access_token=auth.create_access_token(principal),
        refresh_token=auth.create_refresh_token(principal, token_id=next_refresh_id),
        expires_in=request.app.state.config.access_token_ttl_seconds,
    )
    db.store_refresh_token(user_id=principal.user_id, token_id=next_refresh_id, expires_at=auth.refresh_expiry())

    response = JSONResponse(content=pair.model_dump(mode="json"))
    _set_auth_cookies(response, request, pair)
    return response


@router.post("/auth/api/refresh", response_model=TokenPair)
def api_refresh(request: Request, payload_in: RefreshRequest) -> JSONResponse:
    auth: AuthManager = request.app.state.auth
    db = request.app.state.db
    payload = auth.decode_refresh(payload_in.refresh_token)
    token_id = str(payload.get("jti"))
    user = db.use_refresh_token(token_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="refresh token revoked or expired")

    principal = Principal(user_id=user.id, org_id=user.org_id, username=user.username, role=user.role)
    next_refresh_id = secrets.token_urlsafe(24)
    pair = TokenPair(
        access_token=auth.create_access_token(principal),
        refresh_token=auth.create_refresh_token(principal, token_id=next_refresh_id),
        expires_in=request.app.state.config.access_token_ttl_seconds,
    )
    db.store_refresh_token(user_id=principal.user_id, token_id=next_refresh_id, expires_at=auth.refresh_expiry())
    return JSONResponse(content=pair.model_dump(mode="json"))


@router.post("/auth/logout")
def logout(request: Request, principal: Principal = Depends(principal_from_request)) -> RedirectResponse:
    del principal
    csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not csrf_cookie or csrf_cookie != csrf_header:
        raise HTTPException(status_code=403, detail="invalid CSRF token")

    response = RedirectResponse(url="/login", status_code=303)
    _clear_auth_cookies(response)
    return response
