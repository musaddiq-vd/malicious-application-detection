"""Persistence queries for users, sessions and scans.

Every scan query is scoped by ``user_id`` so one account can never read or
modify another account's data.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from maldetect import features as catalog
from maldetect.api import security
from maldetect.api.db import to_iso, utcnow_iso

SUMMARY_COLUMNS = "id, app_name, source, verdict, probability, risk_level, created_at"
STATS_DAYS = 14
TOP_INDICATORS = 8
RECENT_SCANS = 5


# --- users -----------------------------------------------------------------


def user_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "email": row["email"],
        "created_at": row["created_at"],
    }


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def create_user(
    conn: sqlite3.Connection, *, username: str, email: str, full_name: str, password: str
) -> dict[str, Any]:
    """Insert a user; raises ``sqlite3.IntegrityError`` on a duplicate username or email."""
    cursor = conn.execute(
        "INSERT INTO users (username, email, full_name, password_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, email, full_name, security.hash_password(password), utcnow_iso()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return user_to_dict(row)


# --- sessions --------------------------------------------------------------


def create_session(conn: sqlite3.Connection, user_id: int, ttl_hours: int) -> str:
    """Create a session and return the raw token (only its hash is stored)."""
    now = datetime.now(timezone.utc)
    token = security.new_session_token()
    expires = now + timedelta(hours=ttl_hours)
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (to_iso(now),))
    conn.execute(
        "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, security.hash_token(token), to_iso(now), to_iso(expires)),
    )
    conn.commit()
    return token


def get_session_user(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (security.hash_token(token), utcnow_iso()),
    ).fetchone()
    return user_to_dict(row) if row else None


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (security.hash_token(token),))
    conn.commit()


def get_password_hash(conn: sqlite3.Connection, user_id: int) -> str | None:
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    return row["password_hash"] if row else None


def change_password(
    conn: sqlite3.Connection, user_id: int, new_password: str, keep_token: str | None
) -> None:
    """Store a new password hash and sign the user out everywhere else.

    Every other session is revoked so a stolen cookie stops working the moment
    the owner changes their password.
    """
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (security.hash_password(new_password), user_id),
    )
    keep_hash = security.hash_token(keep_token) if keep_token else ""
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, keep_hash)
    )
    conn.commit()


def delete_user(conn: sqlite3.Connection, user_id: int) -> None:
    """Remove the account; sessions and scans go with it via ON DELETE CASCADE."""
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


# --- scans -----------------------------------------------------------------


def summary_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "app_name": row["app_name"],
        "source": row["source"],
        "verdict": row["verdict"],
        "probability": row["probability"],
        "risk_level": row["risk_level"],
        "created_at": row["created_at"],
    }


def scan_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        **summary_to_dict(row),
        "threshold": row["threshold"],
        "model_name": row["model_name"],
        "features": json.loads(row["features"]),
        "contributions": json.loads(row["contributions"]),
        "apk": json.loads(row["apk"]) if row["apk"] else None,
    }


def prediction_to_dict(prediction: Any) -> dict[str, Any]:
    """Convert a predictor result into plain JSON-safe values.

    Attribute access (rather than ``to_dict``) keeps the stored shape under
    this package's control, and the casts strip any numpy scalar types.
    """
    return {
        "verdict": str(prediction.verdict),
        "probability": float(prediction.probability),
        "risk_level": str(prediction.risk_level),
        "threshold": float(prediction.threshold),
        "model_name": str(prediction.model_name),
        "contributions": [
            {
                "slug": str(item.slug),
                "label": str(item.label),
                "category": str(item.category),
                "value": int(item.value),
                "impact": float(item.impact),
            }
            for item in prediction.contributions
        ],
    }


def create_scan(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    app_name: str,
    source: str,
    features: dict[str, int],
    prediction: dict[str, Any],
    apk: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Store a scan. ``created_at`` may be supplied to backdate seeded demo data."""
    cursor = conn.execute(
        "INSERT INTO scans (user_id, app_name, source, verdict, probability, risk_level, "
        "threshold, model_name, features, contributions, apk, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            app_name,
            source,
            prediction["verdict"],
            prediction["probability"],
            prediction["risk_level"],
            prediction["threshold"],
            prediction["model_name"],
            json.dumps(features),
            json.dumps(prediction["contributions"]),
            json.dumps(apk) if apk is not None else None,
            created_at or utcnow_iso(),
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return scan_to_dict(row)


def get_scan(conn: sqlite3.Connection, user_id: int, scan_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
    ).fetchone()
    return scan_to_dict(row) if row else None


def delete_scan(conn: sqlite3.Connection, user_id: int, scan_id: int) -> bool:
    cursor = conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
    conn.commit()
    return cursor.rowcount > 0


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_scans(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    limit: int,
    offset: int,
    verdict: str | None = None,
    query: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return one page of the user's scans (newest first) and the filtered total."""
    where = ["user_id = ?"]
    params: list[Any] = [user_id]
    if verdict:
        where.append("verdict = ?")
        params.append(verdict)
    if query:
        where.append("app_name LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(query)}%")
    # Only fixed fragments are joined here; every value is bound as a parameter.
    clause = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM scans WHERE {clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT {SUMMARY_COLUMNS} FROM scans WHERE {clause} "
        "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return [summary_to_dict(row) for row in rows], total


def compute_stats(
    conn: sqlite3.Connection, user_id: int, *, today: datetime | None = None
) -> dict[str, Any]:
    """Aggregate dashboard statistics for a single user."""
    totals = conn.execute(
        "SELECT COUNT(*) AS total, "
        "COALESCE(SUM(verdict = 'malicious'), 0) AS malicious, "
        "COALESCE(SUM(source = 'apk'), 0) AS apk, "
        "COALESCE(AVG(probability), 0.0) AS avg_probability "
        "FROM scans WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    total = int(totals["total"])
    malicious = int(totals["malicious"])
    apk = int(totals["apk"])

    end = (today or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
    days = [end - timedelta(days=offset) for offset in range(STATS_DAYS - 1, -1, -1)]
    by_day = {day.isoformat(): {"malicious": 0, "benign": 0} for day in days}
    rows = conn.execute(
        "SELECT substr(created_at, 1, 10) AS day, verdict, COUNT(*) AS n FROM scans "
        "WHERE user_id = ? AND created_at >= ? GROUP BY day, verdict",
        (user_id, f"{days[0].isoformat()}T00:00:00Z"),
    ).fetchall()
    for row in rows:
        if row["day"] in by_day:
            by_day[row["day"]][row["verdict"]] = int(row["n"])

    counts: Counter[str] = Counter()
    for row in conn.execute(
        "SELECT features FROM scans WHERE user_id = ? AND verdict = 'malicious'", (user_id,)
    ):
        counts.update(slug for slug, flag in json.loads(row["features"]).items() if flag)
    by_slug = {feature.slug: feature for feature in catalog.FEATURES}
    order = {feature.slug: index for index, feature in enumerate(catalog.FEATURES)}
    ranked = sorted(
        (slug for slug in counts if slug in by_slug),
        key=lambda slug: (-counts[slug], order[slug]),
    )
    top_indicators = [
        {
            "slug": slug,
            "label": by_slug[slug].label,
            "category": by_slug[slug].category,
            "count": counts[slug],
        }
        for slug in ranked[:TOP_INDICATORS]
    ]

    recent, _ = list_scans(conn, user_id, limit=RECENT_SCANS, offset=0)
    return {
        "total_scans": total,
        "malicious": malicious,
        "benign": total - malicious,
        "avg_probability": float(totals["avg_probability"]),
        "detection_rate": malicious / total if total else 0.0,
        "by_day": [{"date": day, **verdicts} for day, verdicts in by_day.items()],
        "by_source": {"manual": total - apk, "apk": apk},
        "top_indicators": top_indicators,
        "recent": recent,
    }
