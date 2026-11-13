"""Seed a demo account with realistic scan history.

Creates the user ``demo`` and about 30 scans spread over the last 14 days so
the dashboard has something to show (this is what the README screenshots use).
Every scan is scored by the real trained model, so the stored probabilities
and feature contributions are genuine.

Usage::

    python scripts/seed_demo.py            # create the demo user and its scans
    python scripts/seed_demo.py --reset    # replace the demo user's existing scans

The password is read from ``MALDETECT_DEMO_PASSWORD``. The built-in default is
published in this repository and is therefore only suitable for a local demo;
never run this script against a deployment that is reachable by others
without setting your own value.

The script is idempotent: running it again leaves existing demo scans alone
unless ``--reset`` is given.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maldetect import features as catalog  # noqa: E402
from maldetect.api import db, security, store  # noqa: E402
from maldetect.api.presets import build_presets  # noqa: E402

DEMO_USERNAME = "demo"
DEMO_FULL_NAME = "Demo Analyst"
DEMO_EMAIL = "demo@example.com"
DEFAULT_DEMO_PASSWORD = "demo-pass-2026"  # local demo only; override via the env var
PASSWORD_ENV = "MALDETECT_DEMO_PASSWORD"

HISTORY_DAYS = 14
APK_SHARE = 0.3

# Plausible app names per preset id; APK-sourced scans turn these into file names.
APP_NAMES: dict[str, tuple[str, ...]] = {
    "sms_fraud_trojan": ("Free Ringtones HD", "Battery Doctor Plus", "Lucky Spin"),
    "spyware": ("System Update Service", "Family Locator Pro", "Sync Helper", "Wi-Fi Booster"),
    "rooting_dropper": ("Super Cleaner Master", "Game Mod Installer", "Root Tools Lite"),
    "flashlight_utility": ("Pocket Torch", "Simple Flashlight", "Bright LED"),
    "messaging_app": ("ChatWave", "Hello Messenger", "TeamTalk"),
    "camera_app": ("SnapLens Camera", "Open Camera", "PhotoPro"),
}

# Benign apps dominate real traffic; malware samples arrive in smaller numbers.
PRESET_WEIGHTS: dict[str, float] = {
    "sms_fraud_trojan": 1.6,
    "spyware": 1.3,
    "rooting_dropper": 1.1,
    "flashlight_utility": 1.8,
    "messaging_app": 2.2,
    "camera_app": 2.0,
}

# Features that commonly differ between otherwise similar apps; toggling one or
# two of these gives each seeded scan its own slightly different profile.
VARIATION_KEYS: tuple[str, ...] = (
    "INTERNET",
    "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE",
    "BLUETOOTH",
    ".zip",
    ".so",
    "System.*loadLibrary",
    "android.intent.action.BOOT_COMPLETED",
)

# Dataset columns that abbreviate the real Android permission name.
PERMISSION_NAMES: dict[str, str] = {"PHONE_STATE": "READ_PHONE_STATE"}

EVIDENCE_BY_CATEGORY: dict[str, str] = {
    "permission": "Declared in AndroidManifest.xml",
    "api_call": "Referenced in classes.dex",
    "intent": "Intent filter in AndroidManifest.xml",
    "command": "Shell command string in classes.dex",
    "file_artifact": "File reference in classes.dex",
}


def demo_password() -> str:
    return os.environ.get(PASSWORD_ENV) or DEFAULT_DEMO_PASSWORD


def ensure_demo_user(conn: Any) -> int:
    """Create the demo user if needed and make sure its password is current."""
    row = store.get_user_by_username(conn, DEMO_USERNAME)
    if row is None:
        user = store.create_user(
            conn,
            username=DEMO_USERNAME,
            email=DEMO_EMAIL,
            full_name=DEMO_FULL_NAME,
            password=demo_password(),
        )
        return int(user["id"])
    if not security.verify_password(demo_password(), row["password_hash"]):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (security.hash_password(demo_password()), row["id"]),
        )
        conn.commit()
    return int(row["id"])


def vary(features: dict[str, int], rng: random.Random) -> dict[str, int]:
    """Flip up to two commonplace features so repeated presets are not identical."""
    slug_by_key = {feature.key: feature.slug for feature in catalog.FEATURES}
    varied = dict(features)
    for key in rng.sample(VARIATION_KEYS, k=rng.choice((0, 1, 1, 2))):
        slug = slug_by_key[key]
        varied[slug] = 1 - varied[slug]
    return varied


def random_moment(now: datetime, rng: random.Random) -> datetime:
    """A working-hours timestamp within the history window, never in the future."""
    day = now.date() - timedelta(days=rng.randrange(HISTORY_DAYS))
    moment = datetime(
        day.year,
        day.month,
        day.day,
        rng.randint(8, 19),
        rng.randrange(60),
        rng.randrange(60),
        tzinfo=timezone.utc,
    )
    if moment > now:
        moment = now - timedelta(minutes=rng.randint(5, 180))
    return moment


def apk_metadata(name: str, features: dict[str, int], rng: random.Random) -> dict[str, Any]:
    """Plausible upload metadata consistent with the scan's feature vector."""
    package = "com." + re.sub(r"[^a-z0-9]+", ".", name.lower()).strip(".")
    permissions: list[str] = []
    evidence: dict[str, str] = {}
    for feature in catalog.FEATURES:
        if not features[feature.slug]:
            continue
        evidence[feature.slug] = EVIDENCE_BY_CATEGORY.get(feature.category, "Found in package")
        if feature.category == "permission":
            permission = PERMISSION_NAMES.get(feature.key, feature.key)
            permissions.append(f"android.permission.{permission}")
    return {
        "package": package,
        "sha256": hashlib.sha256(rng.randbytes(32)).hexdigest(),
        "size_bytes": rng.randint(1_200_000, 48_000_000),
        "dex_count": rng.choice((1, 1, 1, 2, 2, 3)),
        "permissions": sorted(permissions),
        "evidence": evidence,
    }


def seed_scans(conn: Any, user_id: int, predictor: Any, count: int, seed: int) -> dict[str, int]:
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    presets = {preset["id"]: preset for preset in build_presets()}
    preset_ids = list(presets)
    weights = [PRESET_WEIGHTS.get(preset_id, 1.0) for preset_id in preset_ids]

    planned: list[tuple[datetime, dict[str, Any]]] = []
    for _ in range(count):
        preset = presets[rng.choices(preset_ids, weights=weights)[0]]
        name = rng.choice(APP_NAMES.get(preset["id"], (preset["name"],)))
        features = vary(preset["features"], rng)
        is_apk = rng.random() < APK_SHARE
        planned.append(
            (
                random_moment(now, rng),
                {
                    "app_name": name.lower().replace(" ", "-") + ".apk" if is_apk else name,
                    "source": "apk" if is_apk else "manual",
                    "features": features,
                    "apk": apk_metadata(name, features, rng) if is_apk else None,
                },
            )
        )

    # Insert oldest first so ids increase with time, as they would in real use.
    verdicts = {"malicious": 0, "benign": 0}
    for moment, scan in sorted(planned, key=lambda item: item[0]):
        prediction = store.prediction_to_dict(predictor.predict(scan["features"]))
        store.create_scan(
            conn,
            user_id=user_id,
            prediction=prediction,
            created_at=db.to_iso(moment),
            **scan,
        )
        verdicts[prediction["verdict"]] += 1
    return verdicts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the demo user and its scan history.")
    parser.add_argument("--count", type=int, default=30, help="number of scans to create")
    parser.add_argument("--seed", type=int, default=2026, help="random seed for reproducibility")
    parser.add_argument(
        "--reset", action="store_true", help="delete the demo user's existing scans first"
    )
    args = parser.parse_args(argv)

    try:
        from maldetect.ml.predictor import Predictor

        predictor = Predictor.load()
    except FileNotFoundError:
        print(
            "No trained model found. Train it first with: python -m maldetect.ml.train",
            file=sys.stderr,
        )
        return 1

    db.init_db()
    with closing(db.connect()) as conn:
        user_id = ensure_demo_user(conn)
        existing = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
        if existing and not args.reset:
            print(
                f"User '{DEMO_USERNAME}' already has {existing} scans; nothing to do "
                "(use --reset to replace them)."
            )
            return 0
        if existing:
            conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
            conn.commit()
        verdicts = seed_scans(conn, user_id, predictor, args.count, args.seed)

    source = f"${PASSWORD_ENV}" if os.environ.get(PASSWORD_ENV) else "the built-in local default"
    print(
        f"Seeded {sum(verdicts.values())} scans for user '{DEMO_USERNAME}' "
        f"({verdicts['malicious']} malicious, {verdicts['benign']} benign)."
    )
    print(f"Log in as '{DEMO_USERNAME}' with the password from {source}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
