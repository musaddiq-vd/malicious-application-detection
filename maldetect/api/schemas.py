"""Request and response models.

Request validators raise plain ``ValueError`` messages written for end users;
the application's 422 handler forwards them unchanged.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, StrictInt, field_validator

from maldetect import features as catalog

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
EMAIL_RE = re.compile(r"[^@\s]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")
MAX_PASSWORD_LENGTH = 256
MAX_APP_NAME_LENGTH = 120
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value: str) -> str:
    """Drop control characters and surrounding whitespace."""
    return _CONTROL_CHARS.sub("", value).strip()


class RegisterRequest(BaseModel):
    full_name: str
    email: str
    username: str
    password: str

    @field_validator("full_name")
    @classmethod
    def _full_name(cls, value: str) -> str:
        value = clean_text(value)
        if not 2 <= len(value) <= 80:
            raise ValueError("Full name must be between 2 and 80 characters")
        return value

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 254 or not EMAIL_RE.fullmatch(value):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("username")
    @classmethod
    def _username(cls, value: str) -> str:
        value = value.strip()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError(
                "Username must be 3-32 characters: letters, digits, dot, dash or underscore"
            )
        return value

    @field_validator("password")
    @classmethod
    def _password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if len(value) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long")
        if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
            raise ValueError("Password must contain at least one letter and one digit")
        return value


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def _username(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 64:
            raise ValueError("Enter your username")
        return value

    @field_validator("password")
    @classmethod
    def _password(cls, value: str) -> str:
        # Capped so an oversized password cannot be used to burn CPU in scrypt.
        if not value or len(value) > MAX_PASSWORD_LENGTH:
            raise ValueError("Enter your password")
        return value


class ManualScanRequest(BaseModel):
    app_name: str | None = None
    features: dict[str, StrictInt]

    @field_validator("app_name")
    @classmethod
    def _app_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = clean_text(value)
        if len(value) > MAX_APP_NAME_LENGTH:
            raise ValueError(f"App name must be at most {MAX_APP_NAME_LENGTH} characters")
        return value or None

    @field_validator("features")
    @classmethod
    def _features(cls, value: dict[str, int]) -> dict[str, int]:
        known = set(catalog.slugs())
        unknown = sorted(slug for slug in value if slug not in known)
        if unknown:
            raise ValueError(f"Unknown feature: {unknown[0]}")
        for slug, flag in value.items():
            if flag not in (0, 1):
                raise ValueError(f"Feature '{slug}' must be 0 or 1")
        return value


class User(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    created_at: str


class UserEnvelope(BaseModel):
    user: User


class ScanSummary(BaseModel):
    id: int
    app_name: str
    source: Literal["manual", "apk"]
    verdict: Literal["malicious", "benign"]
    probability: float
    risk_level: str
    created_at: str


class ContributionOut(BaseModel):
    slug: str
    label: str
    category: str
    value: int
    impact: float


class ApkInfo(BaseModel):
    package: str | None
    sha256: str
    size_bytes: int
    dex_count: int
    permissions: list[str]
    evidence: dict[str, str]


class Scan(ScanSummary):
    threshold: float
    model_name: str
    features: dict[str, int]
    contributions: list[ContributionOut]
    apk: ApkInfo | None


class ScanPage(BaseModel):
    items: list[ScanSummary]
    total: int


class DayCount(BaseModel):
    date: str
    malicious: int
    benign: int


class SourceCounts(BaseModel):
    manual: int
    apk: int


class Indicator(BaseModel):
    slug: str
    label: str
    category: str
    count: int


class Stats(BaseModel):
    total_scans: int
    malicious: int
    benign: int
    avg_probability: float
    detection_rate: float
    by_day: list[DayCount]
    by_source: SourceCounts
    top_indicators: list[Indicator]
    recent: list[ScanSummary]


class Health(BaseModel):
    status: str
    model_loaded: bool
    version: str
