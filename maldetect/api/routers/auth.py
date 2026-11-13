"""Registration, login, logout and the current-user endpoint."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status

from maldetect import config
from maldetect.api import security, store
from maldetect.api.deps import CurrentUser, Database
from maldetect.api.schemas import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    LoginRequest,
    RegisterRequest,
    UserEnvelope,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_CREDENTIALS = "Invalid username or password"
WRONG_PASSWORD = "Current password is incorrect"


def _start_session(response: Response, conn: sqlite3.Connection, user_id: int) -> None:
    """Issue a fresh session token; a new one per login prevents session fixation."""
    token = store.create_session(conn, user_id, config.SESSION_TTL_HOURS)
    response.set_cookie(
        security.SESSION_COOKIE,
        token,
        max_age=config.SESSION_TTL_HOURS * 3600,
        path="/",
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
    )


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(
        security.SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
    )


@router.post("/register", response_model=UserEnvelope, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, response: Response, conn: Database) -> dict[str, Any]:
    if store.get_user_by_username(conn, payload.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")
    if store.get_user_by_email(conn, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    try:
        user = store.create_user(
            conn,
            username=payload.username,
            email=payload.email,
            full_name=payload.full_name,
            password=payload.password,
        )
    except sqlite3.IntegrityError as exc:
        # Two concurrent registrations can both pass the checks above; the
        # UNIQUE constraints are the final arbiter.
        conn.rollback()
        detail = "Email already registered" if "email" in str(exc) else "Username already taken"
        raise HTTPException(status.HTTP_409_CONFLICT, detail) from exc
    _start_session(response, conn, user["id"])
    return {"user": user}


@router.post("/login", response_model=UserEnvelope)
def login(
    payload: LoginRequest, request: Request, response: Response, conn: Database
) -> dict[str, Any]:
    limiter: security.LoginRateLimiter = request.app.state.login_limiter
    client_ip = request.client.host if request.client else "unknown"
    key = limiter.key(payload.username, client_ip)

    retry_after = limiter.retry_after(key)
    if retry_after:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed login attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    row = store.get_user_by_username(conn, payload.username)
    if row is None:
        security.verify_dummy_password(payload.password)
        valid = False
    else:
        valid = security.verify_password(payload.password, row["password_hash"])
    if row is None or not valid:
        limiter.record_failure(key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    limiter.reset(key)
    _start_session(response, conn, row["id"])
    return {"user": store.user_to_dict(row)}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: CurrentUser, conn: Database) -> Response:
    token = request.cookies.get(security.SESSION_COOKIE)
    if token:
        store.delete_session(conn, token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_cookie(response)
    return response


@router.get("/me", response_model=UserEnvelope)
def me(user: CurrentUser) -> dict[str, Any]:
    return {"user": user}


def _require_password(
    request: Request, conn: sqlite3.Connection, user: dict[str, Any], password: str
) -> None:
    """Re-authenticate before a sensitive account change.

    Shares the login limiter so a hijacked session cannot be used to guess the
    password without limit.
    """
    limiter: security.LoginRateLimiter = request.app.state.login_limiter
    client_ip = request.client.host if request.client else "unknown"
    key = limiter.key(user["username"], client_ip)
    retry_after = limiter.retry_after(key)
    if retry_after:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    stored = store.get_password_hash(conn, user["id"])
    if stored is None or not security.verify_password(password, stored):
        limiter.record_failure(key)
        # 403, not 401: the session is valid, so the client must not sign the user out.
        raise HTTPException(status.HTTP_403_FORBIDDEN, WRONG_PASSWORD)
    limiter.reset(key)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest, request: Request, user: CurrentUser, conn: Database
) -> Response:
    _require_password(request, conn, user, payload.current_password)
    if payload.new_password == payload.current_password:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "New password must be different from the current one",
        )
    store.change_password(
        conn, user["id"], payload.new_password, request.cookies.get(security.SESSION_COOKIE)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    payload: DeleteAccountRequest, request: Request, user: CurrentUser, conn: Database
) -> Response:
    _require_password(request, conn, user, payload.password)
    store.delete_user(conn, user["id"])
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_cookie(response)
    return response
