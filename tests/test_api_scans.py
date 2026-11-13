"""Scan creation, APK upload, history, ownership and statistics."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import FakePredictor
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maldetect import features as catalog
from maldetect.api.routers import scans as scans_router
from maldetect.ml.apk import ApkParseError

SLUGS = catalog.slugs()
SUMMARY_FIELDS = {"id", "app_name", "source", "verdict", "probability", "risk_level", "created_at"}
SCAN_FIELDS = SUMMARY_FIELDS | {"threshold", "model_name", "features", "contributions", "apk"}


def enabled(count: int) -> dict[str, int]:
    """The first ``count`` features switched on (five or more => fake verdict malicious)."""
    return {slug: 1 for slug in SLUGS[:count]}


def make_scan(client: TestClient, name: str, count: int) -> dict:
    response = client.post("/api/scans/manual", json={"app_name": name, "features": enabled(count)})
    assert response.status_code == 201, response.text
    return response.json()


def fake_report(features: dict[str, int] | None = None) -> SimpleNamespace:
    vector = {slug: 0 for slug in SLUGS} | (features or {})
    return SimpleNamespace(
        package="com.example.torch",
        sha256="ab" * 32,
        size_bytes=2048,
        dex_count=2,
        permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
        features=vector,
        evidence={slug: "matched in classes.dex" for slug, flag in vector.items() if flag},
    )


# --- manual scans ----------------------------------------------------------


def test_manual_scan_happy_path(auth_client: TestClient, fake_predictor: FakePredictor) -> None:
    response = auth_client.post(
        "/api/scans/manual", json={"app_name": "  Sketchy Game  ", "features": enabled(6)}
    )

    assert response.status_code == 201
    scan = response.json()
    assert set(scan) == SCAN_FIELDS
    assert scan["app_name"] == "Sketchy Game"
    assert scan["source"] == "manual"
    assert scan["verdict"] == "malicious"
    assert scan["probability"] == pytest.approx(0.65)
    assert scan["risk_level"] == "high"
    assert scan["threshold"] == 0.5
    assert scan["model_name"] == "Fake Model"
    assert scan["apk"] is None
    assert scan["created_at"].endswith("Z")

    # Missing features are stored as explicit zeros, in catalog order.
    assert list(scan["features"]) == SLUGS
    assert sum(scan["features"].values()) == 6
    assert fake_predictor.calls[-1] == scan["features"]

    assert len(scan["contributions"]) == len(SLUGS)
    assert set(scan["contributions"][0]) == {"slug", "label", "category", "value", "impact"}
    impacts = [abs(item["impact"]) for item in scan["contributions"]]
    assert impacts == sorted(impacts, reverse=True)


def test_manual_scan_defaults(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/manual", json={"features": {}})
    assert response.status_code == 201
    scan = response.json()
    assert scan["app_name"] == "Manual scan"
    assert scan["verdict"] == "benign"
    assert scan["risk_level"] == "low"
    assert set(scan["features"].values()) == {0}


def test_manual_scan_rejects_unknown_slug(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/manual", json={"features": {"not_a_feature": 1}})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Unknown feature: not_a_feature",
        "errors": [{"field": "features", "message": "Unknown feature: not_a_feature"}],
    }


@pytest.mark.parametrize("value", [2, -1, 0.5, "1", True, None])
def test_manual_scan_rejects_non_binary_values(auth_client: TestClient, value: object) -> None:
    response = auth_client.post("/api/scans/manual", json={"features": {SLUGS[0]: value}})
    assert response.status_code == 422
    body = response.json()
    assert isinstance(body["detail"], str)
    assert body["errors"][0]["field"].startswith("features")
    assert auth_client.get("/api/scans").json()["total"] == 0


def test_manual_scan_requires_features(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/manual", json={"app_name": "x"})
    assert response.status_code == 422
    assert response.json()["errors"] == [{"field": "features", "message": "features is required"}]


def test_manual_scan_rejects_overlong_name(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/manual", json={"app_name": "n" * 121, "features": {}})
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "app_name"


def test_scans_return_503_when_model_is_missing(auth_client: TestClient, app: FastAPI) -> None:
    app.state.predictor = None

    manual = auth_client.post("/api/scans/manual", json={"features": {}})
    upload = auth_client.post("/api/scans/apk", files={"file": ("a.apk", b"data")})

    for response in (manual, upload):
        assert response.status_code == 503
        assert "python -m maldetect.ml.train" in response.json()["detail"]
    # History stays readable without a model.
    assert auth_client.get("/api/scans").status_code == 200


# --- APK upload ------------------------------------------------------------


def test_apk_upload_happy_path(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_analyze(source: Path) -> SimpleNamespace:
        seen["path"] = source
        seen["content"] = Path(source).read_bytes()
        return fake_report(enabled(7))

    monkeypatch.setattr(scans_router, "analyze_apk", fake_analyze)
    payload = b"PK\x03\x04 pretend apk bytes"

    response = auth_client.post(
        "/api/scans/apk",
        files={"file": ("torch.apk", payload, "application/vnd.android.package-archive")},
    )

    assert response.status_code == 201, response.text
    scan = response.json()
    assert set(scan) == SCAN_FIELDS
    assert scan["source"] == "apk"
    assert scan["app_name"] == "torch.apk"
    assert scan["verdict"] == "malicious"
    assert sum(scan["features"].values()) == 7
    assert scan["apk"] == {
        "package": "com.example.torch",
        "sha256": "ab" * 32,
        "size_bytes": 2048,
        "dex_count": 2,
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "evidence": {slug: "matched in classes.dex" for slug in SLUGS[:7]},
    }
    # The analyzer saw the full upload, and the temp file is gone afterwards.
    assert seen["content"] == payload
    assert not Path(str(seen["path"])).exists()
    assert auth_client.get(f"/api/scans/{scan['id']}").json() == scan


def test_apk_upload_sanitizes_filename(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scans_router, "analyze_apk", lambda source: fake_report())
    hostile = "..\\..\\evil/" + "a" * 300 + ".apk"

    response = auth_client.post("/api/scans/apk", files={"file": (hostile, b"PK data")})

    name = response.json()["app_name"]
    assert response.status_code == 201
    assert "/" not in name and "\\" not in name
    assert len(name) <= 120
    assert name.startswith("aaa")


def test_apk_upload_rejects_non_apk_and_cleans_up(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Path] = []

    def failing_analyze(source: Path) -> SimpleNamespace:
        seen.append(Path(source))
        raise ApkParseError("not a ZIP archive")

    monkeypatch.setattr(scans_router, "analyze_apk", failing_analyze)

    response = auth_client.post("/api/scans/apk", files={"file": ("notes.txt", b"hello world")})

    assert response.status_code == 400
    assert response.json() == {"detail": "Not a valid APK file: not a ZIP archive"}
    assert seen and not seen[0].exists()
    assert auth_client.get("/api/scans").json()["total"] == 0


def test_apk_upload_rejects_garbage_with_the_real_analyzer(auth_client: TestClient) -> None:
    response = auth_client.post(
        "/api/scans/apk", files={"file": ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 256)}
    )
    assert response.status_code == 400
    assert response.json()["detail"].startswith("Not a valid APK file")


def test_apk_upload_rejects_empty_file(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/apk", files={"file": ("empty.apk", b"")})
    assert response.status_code == 400
    assert response.json() == {"detail": "The uploaded file is empty"}


def test_apk_upload_requires_file_field(auth_client: TestClient) -> None:
    response = auth_client.post("/api/scans/apk", files={"other": ("a.apk", b"data")})
    assert response.status_code == 422
    assert response.json()["errors"] == [{"field": "file", "message": "file is required"}]


@pytest.mark.parametrize("extra_bytes", [1, 512 * 1024])
def test_apk_upload_rejects_oversize(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, extra_bytes: int
) -> None:
    """One byte over is caught while spooling; far over is refused from Content-Length."""
    called: list[Path] = []
    monkeypatch.setattr(scans_router, "analyze_apk", lambda source: called.append(source))
    monkeypatch.setattr("maldetect.config.MAX_UPLOAD_BYTES", 1024 * 1024)

    response = auth_client.post(
        "/api/scans/apk", files={"file": ("big.apk", b"\0" * (1024 * 1024 + extra_bytes))}
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "File is too large. The maximum upload size is 1 MB."}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert called == []


def test_apk_upload_at_exact_limit_is_accepted(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scans_router, "analyze_apk", lambda source: fake_report())
    monkeypatch.setattr("maldetect.config.MAX_UPLOAD_BYTES", 4096)

    response = auth_client.post("/api/scans/apk", files={"file": ("ok.apk", b"\0" * 4096)})
    assert response.status_code == 201


# --- history ---------------------------------------------------------------


def test_list_is_newest_first_with_summary_shape(auth_client: TestClient) -> None:
    ids = [make_scan(auth_client, f"app-{index}", index)["id"] for index in range(3)]

    body = auth_client.get("/api/scans").json()

    assert body["total"] == 3
    assert [item["id"] for item in body["items"]] == ids[::-1]
    assert all(set(item) == SUMMARY_FIELDS for item in body["items"])


def test_list_pagination(auth_client: TestClient) -> None:
    ids = [make_scan(auth_client, f"app-{index}", 0)["id"] for index in range(5)]

    first = auth_client.get("/api/scans", params={"limit": 2, "offset": 0}).json()
    second = auth_client.get("/api/scans", params={"limit": 2, "offset": 2}).json()
    last = auth_client.get("/api/scans", params={"limit": 2, "offset": 4}).json()
    beyond = auth_client.get("/api/scans", params={"limit": 2, "offset": 10}).json()

    assert [first["total"], second["total"], last["total"], beyond["total"]] == [5, 5, 5, 5]
    paged = [item["id"] for page in (first, second, last) for item in page["items"]]
    assert paged == ids[::-1]
    assert beyond["items"] == []


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"verdict": "unknown"}, {"limit": "x"}]
)
def test_list_rejects_bad_query_parameters(auth_client: TestClient, params: dict) -> None:
    response = auth_client.get("/api/scans", params=params)
    assert response.status_code == 422
    body = response.json()
    assert isinstance(body["detail"], str)
    assert body["errors"][0]["field"] == next(iter(params))


def test_list_filter_by_verdict(auth_client: TestClient) -> None:
    make_scan(auth_client, "clean-one", 0)
    make_scan(auth_client, "dirty-one", 8)
    make_scan(auth_client, "dirty-two", 9)

    malicious = auth_client.get("/api/scans", params={"verdict": "malicious"}).json()
    benign = auth_client.get("/api/scans", params={"verdict": "benign"}).json()

    assert malicious["total"] == 2
    assert {item["app_name"] for item in malicious["items"]} == {"dirty-one", "dirty-two"}
    assert benign["total"] == 1
    assert benign["items"][0]["app_name"] == "clean-one"


def test_list_search_is_case_insensitive_and_literal(auth_client: TestClient) -> None:
    make_scan(auth_client, "Flashlight Pro", 0)
    make_scan(auth_client, "flash_sale", 8)
    make_scan(auth_client, "100% legit", 0)
    make_scan(auth_client, "Camera", 0)

    def names(**params: object) -> set[str]:
        body = auth_client.get("/api/scans", params=params).json()
        assert body["total"] == len(body["items"])
        return {item["app_name"] for item in body["items"]}

    assert names(q="FLASH") == {"Flashlight Pro", "flash_sale"}
    assert names(q="flash", verdict="malicious") == {"flash_sale"}
    # LIKE wildcards in the search text are matched literally.
    assert names(q="%") == {"100% legit"}
    assert names(q="_") == {"flash_sale"}
    assert names(q="nothing-matches") == set()
    assert names(q="'; DROP TABLE scans;--") == set()
    assert auth_client.get("/api/scans").json()["total"] == 4


# --- ownership -------------------------------------------------------------


def test_users_only_see_their_own_scans(auth_client: TestClient, other_client: TestClient) -> None:
    mine = make_scan(auth_client, "alice-app", 8)
    theirs = make_scan(other_client, "bob-app", 0)

    assert [item["id"] for item in auth_client.get("/api/scans").json()["items"]] == [mine["id"]]
    assert [item["id"] for item in other_client.get("/api/scans").json()["items"]] == [theirs["id"]]

    # Another user's scan looks exactly like a missing one: 404, never 403.
    for response in (
        other_client.get(f"/api/scans/{mine['id']}"),
        other_client.delete(f"/api/scans/{mine['id']}"),
    ):
        assert response.status_code == 404
        assert response.json() == {"detail": "Scan not found"}
    assert auth_client.get(f"/api/scans/{mine['id']}").status_code == 200

    stats = other_client.get("/api/stats").json()
    assert stats["total_scans"] == 1
    assert stats["malicious"] == 0
    assert stats["top_indicators"] == []
    assert [item["id"] for item in stats["recent"]] == [theirs["id"]]


def test_get_and_delete_scan(auth_client: TestClient) -> None:
    scan = make_scan(auth_client, "to-delete", 2)

    assert auth_client.get(f"/api/scans/{scan['id']}").json() == scan

    deleted = auth_client.delete(f"/api/scans/{scan['id']}")
    assert deleted.status_code == 204
    assert deleted.content == b""
    assert auth_client.get(f"/api/scans/{scan['id']}").status_code == 404
    assert auth_client.delete(f"/api/scans/{scan['id']}").status_code == 404
    assert auth_client.get("/api/scans").json() == {"items": [], "total": 0}


def test_scan_id_must_be_an_integer(auth_client: TestClient) -> None:
    response = auth_client.get("/api/scans/abc")
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "scan_id"


# --- stats -----------------------------------------------------------------


def test_stats_for_a_new_user_are_zero_filled(auth_client: TestClient) -> None:
    stats = auth_client.get("/api/stats").json()

    assert set(stats) == {
        "total_scans",
        "malicious",
        "benign",
        "avg_probability",
        "detection_rate",
        "by_day",
        "by_source",
        "top_indicators",
        "recent",
    }
    assert stats["total_scans"] == stats["malicious"] == stats["benign"] == 0
    assert stats["avg_probability"] == 0.0
    assert stats["detection_rate"] == 0.0
    assert stats["by_source"] == {"manual": 0, "apk": 0}
    assert stats["top_indicators"] == []
    assert stats["recent"] == []

    today = datetime.now(timezone.utc).date()
    expected_days = [(today - timedelta(days=offset)).isoformat() for offset in range(13, -1, -1)]
    assert [day["date"] for day in stats["by_day"]] == expected_days
    assert all(day["malicious"] == 0 and day["benign"] == 0 for day in stats["by_day"])


def test_stats_aggregates(
    auth_client: TestClient, db_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scans_router, "analyze_apk", lambda source: fake_report(enabled(6)))
    benign = make_scan(auth_client, "clean", 0)  # p = 0.05
    old = make_scan(auth_client, "old-malware", 5)  # p = 0.55
    ancient = make_scan(auth_client, "ancient", 0)  # p = 0.05, outside the 14-day window
    make_scan(auth_client, "malware", 7)  # p = 0.75
    upload = auth_client.post("/api/scans/apk", files={"file": ("x.apk", b"PK")})  # p = 0.65
    assert upload.status_code == 201

    now = datetime.now(timezone.utc)
    three_days_ago = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    long_ago = (now - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE id = ?", (three_days_ago, old["id"]))
        conn.execute("UPDATE scans SET created_at = ? WHERE id = ?", (long_ago, ancient["id"]))
        conn.commit()

    stats = auth_client.get("/api/stats").json()

    assert stats["total_scans"] == 5
    assert stats["malicious"] == 3
    assert stats["benign"] == 2
    assert stats["detection_rate"] == pytest.approx(0.6)
    assert stats["avg_probability"] == pytest.approx((0.05 + 0.55 + 0.05 + 0.75 + 0.65) / 5)
    assert stats["by_source"] == {"manual": 4, "apk": 1}

    by_day = {day["date"]: day for day in stats["by_day"]}
    assert len(by_day) == 14
    today = now.date()
    assert by_day[today.isoformat()] == {
        "date": today.isoformat(),
        "malicious": 2,
        "benign": 1,
    }
    earlier = (today - timedelta(days=3)).isoformat()
    assert by_day[earlier] == {"date": earlier, "malicious": 1, "benign": 0}
    assert sum(day["malicious"] + day["benign"] for day in stats["by_day"]) == 4

    # Feature i is enabled in every malicious scan that switched on more than i features.
    indicators = stats["top_indicators"]
    assert len(indicators) == 7
    assert set(indicators[0]) == {"slug", "label", "category", "count"}
    assert [item["slug"] for item in indicators] == SLUGS[:7]
    assert [item["count"] for item in indicators] == [3, 3, 3, 3, 3, 2, 1]
    assert indicators[0]["label"] == catalog.by_slug(SLUGS[0]).label

    assert len(stats["recent"]) == 5
    assert all(set(item) == SUMMARY_FIELDS for item in stats["recent"])
    assert stats["recent"][-1]["id"] == ancient["id"]
    assert benign["id"] in {item["id"] for item in stats["recent"]}


def test_top_indicators_are_capped_at_eight(auth_client: TestClient) -> None:
    make_scan(auth_client, "everything", 12)
    indicators = auth_client.get("/api/stats").json()["top_indicators"]
    assert len(indicators) == 8


def test_recent_is_capped_at_five(auth_client: TestClient) -> None:
    ids = [make_scan(auth_client, f"app-{index}", 0)["id"] for index in range(7)]
    recent = auth_client.get("/api/stats").json()["recent"]
    assert [item["id"] for item in recent] == ids[::-1][:5]
