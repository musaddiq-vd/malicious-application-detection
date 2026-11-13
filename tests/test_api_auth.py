"""Registration, login, sessions and the login rate limiter."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from pathlib import Path

import pytest
from conftest import DEFAULT_PASSWORD, register_user
from fastapi.testclient import TestClient

from maldetect.api import security

COOKIE = security.SESSION_COOKIE

VALID_REGISTRATION = {
    "full_name": "Alice Analyst",
    "email": "alice@example.com",
    "username": "alice",
    "password": DEFAULT_PASSWORD,
}


def _rows(db_file: Path, sql: str) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_file)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql).fetchall()


def test_register_creates_user_and_logs_in(client: TestClient) -> None:
    response = client.post("/api/auth/register", json=VALID_REGISTRATION)

    assert response.status_code == 201
    user = response.json()["user"]
    assert set(user) == {"id", "username", "full_name", "email", "created_at"}
    assert user["username"] == "alice"
    assert user["email"] == "alice@example.com"
    assert user["created_at"].endswith("Z")
    assert client.get("/api/auth/me").json() == {"user": user}


def test_session_cookie_flags(client: TestClient) -> None:
    response = client.post("/api/auth/register", json=VALID_REGISTRATION)

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    lowered = cookie.lower()
    assert "httponly" in lowered
    assert "samesite=lax" in lowered
    assert "path=/" in lowered
    assert "max-age=" in lowered
    assert "secure" not in lowered  # only set when MALDETECT_COOKIE_SECURE=1


def test_cookie_secure_flag_follows_config(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("maldetect.config.COOKIE_SECURE", True)
    response = client.post("/api/auth/register", json=VALID_REGISTRATION)
    assert "secure" in response.headers["set-cookie"].lower()


def test_password_and_token_are_never_stored_in_clear(client: TestClient, db_file: Path) -> None:
    client.post("/api/auth/register", json=VALID_REGISTRATION)
    token = client.cookies.get(COOKIE)

    stored = _rows(db_file, "SELECT password_hash FROM users")[0]["password_hash"]
    assert stored.startswith("scrypt$")
    assert DEFAULT_PASSWORD not in stored

    session = _rows(db_file, "SELECT token_hash FROM sessions")[0]["token_hash"]
    assert session != token
    assert session == hashlib.sha256(token.encode()).hexdigest()


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("username", "ab", "Username"),
        ("username", "has space", "Username"),
        ("username", "x" * 33, "Username"),
        ("email", "not-an-email", "email"),
        ("email", "a@b", "email"),
        ("password", "short1", "at least 8"),
        ("password", "onlyletters", "letter and one digit"),
        ("password", "1234567890", "letter and one digit"),
        ("full_name", "A", "Full name"),
        ("full_name", "N" * 81, "Full name"),
    ],
)
def test_register_validation_errors_are_flattened(
    client: TestClient, field: str, value: str, fragment: str
) -> None:
    response = client.post("/api/auth/register", json={**VALID_REGISTRATION, field: value})

    assert response.status_code == 422
    body = response.json()
    assert set(body) == {"detail", "errors"}
    assert body["errors"] == [{"field": field, "message": body["detail"]}]
    assert fragment in body["detail"]
    assert not body["detail"].startswith("Value error")


def test_register_reports_every_invalid_field(client: TestClient) -> None:
    response = client.post("/api/auth/register", json={"username": "ok_name", "password": "x"})

    body = response.json()
    assert response.status_code == 422
    assert {error["field"] for error in body["errors"]} == {"full_name", "email", "password"}
    assert body["detail"] == body["errors"][0]["message"]
    assert {"field": "email", "message": "email is required"} in body["errors"]


def test_malformed_json_is_a_flat_422(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)
    assert response.json()["errors"]


def test_duplicate_username_is_rejected_case_insensitively(client: TestClient) -> None:
    client.post("/api/auth/register", json=VALID_REGISTRATION)
    response = client.post(
        "/api/auth/register",
        json={**VALID_REGISTRATION, "username": "ALICE", "email": "other@example.com"},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Username already taken"}


def test_duplicate_email_is_rejected(client: TestClient) -> None:
    client.post("/api/auth/register", json=VALID_REGISTRATION)
    response = client.post(
        "/api/auth/register",
        json={**VALID_REGISTRATION, "username": "alice2", "email": "Alice@Example.com"},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Email already registered"}


def test_login_logout_roundtrip(client: TestClient) -> None:
    user = register_user(client, "alice")
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    response = client.post(
        "/api/auth/login", json={"username": "alice", "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200
    assert response.json() == {"user": user}
    assert client.get("/api/auth/me").status_code == 200


def test_logout_invalidates_the_session_server_side(client: TestClient, db_file: Path) -> None:
    register_user(client, "alice")
    token = client.cookies.get(COOKIE)

    response = client.post("/api/auth/logout")
    assert response.status_code == 204
    assert response.content == b""
    assert _rows(db_file, "SELECT COUNT(*) AS n FROM sessions")[0]["n"] == 0

    # Replaying the old cookie must not work even though the client still has it.
    client.cookies.set(COOKIE, token)
    assert client.get("/api/auth/me").status_code == 401


def test_logout_requires_authentication(client: TestClient) -> None:
    response = client.post("/api/auth/logout")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_expired_session_is_rejected(client: TestClient, db_file: Path) -> None:
    register_user(client, "alice")
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'")
        conn.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_forged_cookie_is_rejected(client: TestClient) -> None:
    client.cookies.set(COOKIE, "not-a-real-token")
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


@pytest.mark.parametrize(
    "credentials",
    [
        {"username": "alice", "password": "wrong-password-1"},
        {"username": "nobody", "password": DEFAULT_PASSWORD},
    ],
)
def test_login_failure_does_not_reveal_which_part_was_wrong(
    client: TestClient, credentials: dict[str, str]
) -> None:
    register_user(client, "alice")
    client.post("/api/auth/logout")

    response = client.post("/api/auth/login", json=credentials)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}
    assert "set-cookie" not in response.headers


def test_login_username_is_case_insensitive(client: TestClient) -> None:
    register_user(client, "alice")
    response = client.post(
        "/api/auth/login", json={"username": "Alice", "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200


@pytest.fixture
def registered(client_factory: Callable[[], TestClient]) -> Iterator[TestClient]:
    """An anonymous client for an app where ``alice`` already exists."""
    register_user(client_factory(), "alice")
    yield client_factory()


def test_login_is_rate_limited_after_five_failures(registered: TestClient) -> None:
    bad = {"username": "alice", "password": "wrong-password-1"}
    for _ in range(5):
        assert registered.post("/api/auth/login", json=bad).status_code == 401

    blocked = registered.post("/api/auth/login", json=bad)
    assert blocked.status_code == 429
    assert "Too many failed login attempts" in blocked.json()["detail"]
    assert int(blocked.headers["retry-after"]) > 0

    # Even the right password is refused while the lock is active.
    good = {"username": "alice", "password": DEFAULT_PASSWORD}
    assert registered.post("/api/auth/login", json=good).status_code == 429


def test_rate_limit_is_per_username(registered: TestClient) -> None:
    for _ in range(6):
        registered.post("/api/auth/login", json={"username": "mallory", "password": "nope-1234"})

    response = registered.post(
        "/api/auth/login", json={"username": "alice", "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200


def test_successful_login_resets_the_failure_count(registered: TestClient) -> None:
    bad = {"username": "alice", "password": "wrong-password-1"}
    good = {"username": "alice", "password": DEFAULT_PASSWORD}
    for _ in range(4):
        assert registered.post("/api/auth/login", json=bad).status_code == 401
    assert registered.post("/api/auth/login", json=good).status_code == 200
    for _ in range(4):
        assert registered.post("/api/auth/login", json=bad).status_code == 401
    assert registered.post("/api/auth/login", json=good).status_code == 200


def test_password_hashing_roundtrip() -> None:
    first = security.hash_password("s3cret-password")
    second = security.hash_password("s3cret-password")

    assert first != second  # per-hash random salt
    assert first.split("$")[:4] == ["scrypt", "16384", "8", "1"]
    assert security.verify_password("s3cret-password", first)
    assert not security.verify_password("s3cret-passwore", first)
    assert not security.verify_password("s3cret-password", "plaintext")
    assert not security.verify_password("s3cret-password", "md5$1$2$3$4$5")


def test_rate_limiter_window_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["now"])
    limiter = security.LoginRateLimiter(max_failures=2, window_seconds=60)
    key = limiter.key("Alice ", "127.0.0.1")
    assert key == "alice|127.0.0.1"

    limiter.record_failure(key)
    assert limiter.retry_after(key) == 0
    limiter.record_failure(key)
    assert limiter.retry_after(key) > 0

    clock["now"] += 61
    assert limiter.retry_after(key) == 0
