"""Central paths and runtime settings.

Everything resolves relative to the repository root so the project works from any
checkout location. Settings that tests need to override are exposed as functions
that re-read the environment on every call.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT_DIR: Path = Path(__file__).resolve().parent.parent

DATA_PATH: Path = ROOT_DIR / "data" / "android_malware_features.csv"
MODEL_DIR: Path = ROOT_DIR / "models"
MODEL_PATH: Path = MODEL_DIR / "model.joblib"
METRICS_PATH: Path = MODEL_DIR / "metrics.json"
FIGURES_DIR: Path = ROOT_DIR / "reports" / "figures"
WEB_DIR: Path = ROOT_DIR / "web"
INSTANCE_DIR: Path = ROOT_DIR / "instance"

SESSION_TTL_HOURS: int = 24 * 7


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def db_path() -> Path:
    """SQLite database location; re-read on each call so tests can set MALDETECT_DB."""
    override = os.environ.get("MALDETECT_DB", "").strip()
    return Path(override) if override else INSTANCE_DIR / "maldetect.db"


def max_upload_bytes() -> int:
    """Largest accepted APK upload, from MALDETECT_MAX_UPLOAD_MB (default 100 MB)."""
    return _env_int("MALDETECT_MAX_UPLOAD_MB", 100) * 1024 * 1024


def cookie_secure() -> bool:
    """Whether the session cookie is marked Secure (enable behind HTTPS)."""
    return os.environ.get("MALDETECT_COOKIE_SECURE", "").strip() == "1"


# Import-time snapshots for convenience; prefer the functions above where the
# value may be overridden after import (tests, embedding).
DB_PATH: Path = db_path()
MAX_UPLOAD_BYTES: int = max_upload_bytes()
COOKIE_SECURE: bool = cookie_secure()
