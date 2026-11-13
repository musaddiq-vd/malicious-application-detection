"""Health, catalog endpoints, auth enforcement, security headers and SPA serving."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import register_user
from fastapi import FastAPI
from fastapi.testclient import TestClient

import maldetect
from maldetect import config
from maldetect import features as catalog
from maldetect.api import presets as presets_module
from maldetect.api.app import create_app

PROTECTED_ROUTES = [
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/features"),
    ("GET", "/api/features/presets"),
    ("GET", "/api/model/metrics"),
    ("POST", "/api/scans/manual"),
    ("POST", "/api/scans/apk"),
    ("GET", "/api/scans"),
    ("GET", "/api/scans/1"),
    ("DELETE", "/api/scans/1"),
    ("GET", "/api/stats"),
]


# --- health ----------------------------------------------------------------


def test_health_with_model(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "model_loaded": True,
        "version": maldetect.__version__,
    }


def test_health_without_model(client: TestClient, app: FastAPI) -> None:
    app.state.predictor = None
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["model_loaded"] is False


def test_app_starts_when_the_model_file_is_missing(
    db_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing_model() -> None:
        raise FileNotFoundError(tmp_path / "model.joblib")

    predictor_module = pytest.importorskip("maldetect.ml.predictor")
    monkeypatch.setattr(predictor_module.Predictor, "load", staticmethod(missing_model))

    with TestClient(create_app()) as client:
        assert client.get("/api/health").json()["model_loaded"] is False
        register_user(client, "alice")
        response = client.post("/api/scans/manual", json={"features": {}})
        assert response.status_code == 503
        assert "python -m maldetect.ml.train" in response.json()["detail"]


# --- authentication is enforced everywhere ---------------------------------


@pytest.mark.parametrize(("method", "path"), PROTECTED_ROUTES)
def test_protected_routes_require_authentication(
    client: TestClient, method: str, path: str
) -> None:
    response = client.request(method, path)
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_every_api_route_is_covered_by_the_auth_test(app: FastAPI) -> None:
    """Guards against adding an endpoint without deciding whether it needs auth."""
    public = {
        ("GET", "/api/health"),
        ("POST", "/api/auth/register"),
        ("POST", "/api/auth/login"),
    }
    declared = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    protected = {(method, path.replace("/1", "/{scan_id}")) for method, path in PROTECTED_ROUTES}
    assert declared == public | protected


# --- catalog ---------------------------------------------------------------


def test_features_catalog(auth_client: TestClient) -> None:
    body = auth_client.get("/api/features").json()

    assert set(body) == {"features", "categories"}
    assert len(body["features"]) == len(catalog.FEATURES) == 35
    assert [item["slug"] for item in body["features"]] == catalog.slugs()
    assert all(
        set(item) == {"slug", "label", "category", "description"} for item in body["features"]
    )
    assert body["categories"] == catalog.CATEGORIES
    assert {item["category"] for item in body["features"]} <= set(body["categories"])


def test_presets(auth_client: TestClient) -> None:
    presets = auth_client.get("/api/features/presets").json()["presets"]

    assert 5 <= len(presets) <= 6
    assert len({preset["id"] for preset in presets}) == len(presets)
    assert {preset["expected"] for preset in presets} == {"malicious", "benign"}
    for preset in presets:
        assert set(preset) == {"id", "name", "description", "expected", "features"}
        assert list(preset["features"]) == catalog.slugs()
        assert set(preset["features"].values()) <= {0, 1}
        assert sum(preset["features"].values()) >= 1


def test_presets_reference_real_dataset_columns() -> None:
    header = config.DATA_PATH.read_text(encoding="utf-8").splitlines()[0].split(",")
    for spec in presets_module.PRESET_SPECS:
        assert set(spec.keys) <= set(header), spec.id
        assert len(set(spec.keys)) == len(spec.keys), spec.id


def test_presets_fail_fast_on_unknown_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    broken = presets_module.PresetSpec(
        id="broken", name="Broken", description="", expected="benign", keys=("NO_SUCH_COLUMN",)
    )
    monkeypatch.setattr(presets_module, "PRESET_SPECS", (broken,))
    presets_module.build_presets.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="NO_SUCH_COLUMN"):
            presets_module.build_presets()
    finally:
        presets_module.build_presets.cache_clear()


def test_presets_can_be_submitted_as_scans(auth_client: TestClient) -> None:
    for preset in auth_client.get("/api/features/presets").json()["presets"]:
        response = auth_client.post(
            "/api/scans/manual", json={"app_name": preset["name"], "features": preset["features"]}
        )
        assert response.status_code == 201, response.text


def test_model_metrics_are_served_verbatim(
    auth_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics = {"best_model": "Random Forest", "threshold": 0.42, "models": [{"name": "x"}]}
    path = tmp_path / "metrics.json"
    path.write_text(json.dumps(metrics), encoding="utf-8")
    monkeypatch.setattr(config, "METRICS_PATH", path)

    response = auth_client.get("/api/model/metrics")
    assert response.status_code == 200
    assert response.json() == metrics


def test_model_metrics_missing(
    auth_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "METRICS_PATH", tmp_path / "absent.json")
    response = auth_client.get("/api/model/metrics")
    assert response.status_code == 503
    assert "python -m maldetect.ml.train" in response.json()["detail"]


# --- errors and headers ----------------------------------------------------


def test_unknown_api_path_is_json_404(client: TestClient) -> None:
    for method in ("GET", "POST", "DELETE"):
        response = client.request(method, "/api/does/not/exist")
        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}


def test_security_headers_on_api_responses(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    policy = response.headers["content-security-policy"]
    assert "default-src 'self'" in policy
    assert "script-src 'self';" in policy
    assert "frame-ancestors 'none'" in policy
    assert "https://fonts.googleapis.com" in policy
    assert "https://fonts.gstatic.com" in policy


def test_security_headers_on_error_responses(client: TestClient) -> None:
    response = client.get("/api/stats")
    assert response.status_code == 401
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in response.headers


def test_oversized_json_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "alice", "password": "p" * (300 * 1024)}
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body is too large."}


def test_oversized_chunked_body_is_rejected(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"username": "alice", "password": "'
        for _ in range(40):
            yield b"p" * 8192
        yield b'"}'

    response = client.post(
        "/api/auth/login", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body is too large."}


def test_unhandled_errors_return_generic_json(app: FastAPI) -> None:
    class Boom:
        def predict(self, features: dict[str, int]) -> None:
            raise RuntimeError("secret internal detail")

    with TestClient(app, raise_server_exceptions=False) as quiet:
        register_user(quiet, "alice")
        app.state.predictor = Boom()

        response = quiet.post("/api/scans/manual", json={"features": {}})
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error"}


# --- single-page app -------------------------------------------------------


@pytest.fixture
def web_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "web"
    (directory / "js").mkdir(parents=True)
    monkeypatch.setattr(config, "WEB_DIR", directory)
    return directory


def test_spa_without_index_returns_json_404(client: TestClient, web_dir: Path) -> None:
    for path in ("/", "/dashboard"):
        response = client.get(path)
        assert response.status_code == 404
        assert "detail" in response.json()


def test_spa_serves_index_assets_and_fallback(client: TestClient, web_dir: Path) -> None:
    (web_dir / "index.html").write_text("<!doctype html><title>shell</title>", encoding="utf-8")
    (web_dir / "js" / "app.js").write_text("console.log('hi')", encoding="utf-8")
    (tmp_secret := web_dir.parent / "secret.txt").write_text("top secret", encoding="utf-8")
    assert tmp_secret.exists()

    for path in ("/", "/index.html", "/scans/42", "/login"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.headers["content-type"].startswith("text/html")
        assert "shell" in response.text
        assert response.headers["x-frame-options"] == "DENY"

    asset = client.get("/js/app.js")
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]
    assert asset.text == "console.log('hi')"

    # Missing assets are a 404, not the HTML shell.
    missing = client.get("/js/missing.js")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not found"}

    # Files outside web/ are never served.
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/js/..%2f..%2fsecret.txt"):
        assert "top secret" not in client.get(path).text


def test_spa_fallback_does_not_swallow_api_paths(client: TestClient, web_dir: Path) -> None:
    (web_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    response = client.get("/api/unknown")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


# --- real model ------------------------------------------------------------


@pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="model has not been trained yet")
def test_manual_scan_with_the_real_model(db_file: Path) -> None:
    with TestClient(create_app()) as client:
        assert client.get("/api/health").json()["model_loaded"] is True
        register_user(client, "alice")
        presets = client.get("/api/features/presets").json()["presets"]

        for preset in presets:
            response = client.post(
                "/api/scans/manual",
                json={"app_name": preset["name"], "features": preset["features"]},
            )
            assert response.status_code == 201, response.text
            scan = response.json()
            assert scan["verdict"] in {"malicious", "benign"}
            assert 0.0 <= scan["probability"] <= 1.0
            assert scan["risk_level"] in {"low", "medium", "high", "critical"}
            assert scan["features"] == preset["features"]
            assert len(scan["contributions"]) == 35
            impacts = [abs(item["impact"]) for item in scan["contributions"]]
            assert impacts == sorted(impacts, reverse=True)

        assert client.get("/api/stats").json()["total_scans"] == len(presets)
