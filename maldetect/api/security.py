"""Password hashing, session tokens and the login rate limiter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from functools import lru_cache

SESSION_COOKIE = "maldetect_session"

# scrypt cost parameters (about 16 MiB of memory per hash). They are stored
# alongside every hash so they can be raised later without invalidating
# existing accounts.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=_SCRYPT_MAXMEM
    )


def hash_password(password: str) -> str:
    """Return ``scrypt$n$r$p$salt$hash`` with a fresh random salt."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored hash in constant time."""
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = _scrypt(password, salt, int(n), int(r), int(p), len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password(secrets.token_urlsafe(16))


def verify_dummy_password(password: str) -> None:
    """Spend the same work as a real check when the username does not exist.

    Without this, unknown usernames would answer measurably faster than known
    ones and the login endpoint would leak which accounts exist.
    """
    verify_password(password, _dummy_hash())


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only this digest is persisted, so a leaked database cannot be replayed as cookies."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LoginRateLimiter:
    """In-memory sliding window of failed logins per (username, client IP)."""

    def __init__(
        self, max_failures: int = 5, window_seconds: float = 300.0, max_keys: int = 10_000
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._max_keys = max_keys
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(username: str, client_ip: str) -> str:
        return f"{username.strip().lower()}|{client_ip}"

    def _prune(self, key: str, now: float) -> deque[float] | None:
        attempts = self._failures.get(key)
        if attempts is None:
            return None
        while attempts and now - attempts[0] >= self.window_seconds:
            attempts.popleft()
        if not attempts:
            del self._failures[key]
            return None
        return attempts

    def retry_after(self, key: str) -> int:
        """Seconds until another attempt is allowed; 0 when not blocked."""
        now = time.monotonic()
        with self._lock:
            attempts = self._prune(key, now)
            if attempts is None or len(attempts) < self.max_failures:
                return 0
            return max(1, int(self.window_seconds - (now - attempts[0])) + 1)

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._failures) >= self._max_keys:
                # Bound memory under a username-spraying attack.
                for stale in list(self._failures):
                    self._prune(stale, now)
                if len(self._failures) >= self._max_keys:
                    self._failures.pop(next(iter(self._failures)))
            self._failures.setdefault(key, deque()).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
