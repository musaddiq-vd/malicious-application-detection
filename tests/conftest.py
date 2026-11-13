"""Shared fixtures for the API tests.

Nothing here is autouse: tests that do not request these fixtures (for example
the ML unit tests) run without any database or application being created.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maldetect import features as catalog

DEFAULT_PASSWORD = "correct-horse-7"


@dataclass(frozen=True)
class FakeContribution:
    slug: str
    label: str
    category: str
    value: int
    impact: float


@dataclass(frozen=True)
class FakePrediction:
    verdict: str
    probability: float
    risk_level: str
    threshold: float
    model_name: str
    contributions: list[FakeContribution]


class FakePredictor:
    """Deterministic stand-in for the trained model.

    The probability grows by 0.1 per enabled feature, so tests choose a verdict
    simply by how many features they switch on (five or more is malicious).
    """

    threshold = 0.5
    model_name = "Fake Model"

    def __init__(self) -> None:
        self.calls: list[dict[str, int]] = []

    def predict(self, features: Mapping[str, int]) -> FakePrediction:
        known = set(catalog.slugs())
        for slug, value in features.items():
            if slug not in known:
                raise ValueError(f"Unknown feature: {slug}")
            if value not in (0, 1):
                raise ValueError(f"Feature '{slug}' must be 0 or 1")
        self.calls.append(dict(features))
        enabled = sum(features.values())
        probability = min(0.99, round(0.05 + 0.1 * enabled, 4))
        if probability < 0.25:
            risk_level = "low"
        elif probability < 0.5:
            risk_level = "medium"
        elif probability < 0.8:
            risk_level = "high"
        else:
            risk_level = "critical"
        contributions = [
            FakeContribution(
                slug=feature.slug,
                label=feature.label,
                category=feature.category,
                value=int(features.get(feature.slug, 0)),
                impact=0.1 * int(features.get(feature.slug, 0)),
            )
            for feature in catalog.FEATURES
        ]
        contributions.sort(key=lambda item: abs(item.impact), reverse=True)
        return FakePrediction(
            verdict="malicious" if probability >= self.threshold else "benign",
            probability=probability,
            risk_level=risk_level,
            threshold=self.threshold,
            model_name=self.model_name,
            contributions=contributions,
        )


def register_user(client: TestClient, username: str, password: str = DEFAULT_PASSWORD) -> dict:
    """Register (and thereby log in) a user on ``client``; returns the user payload."""
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": f"{username.title()} Tester",
            "email": f"{username}@example.com",
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["user"]


@pytest.fixture
def db_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the application at a throwaway SQLite file."""
    path = tmp_path / "maldetect-test.db"
    monkeypatch.setenv("MALDETECT_DB", str(path))
    return path


@pytest.fixture
def fake_predictor() -> FakePredictor:
    return FakePredictor()


@pytest.fixture
def app(db_file: Path, fake_predictor: FakePredictor) -> FastAPI:
    """An application backed by the temp database and the fake predictor."""
    from maldetect.api.app import create_app

    application = create_app(load_model=False)
    application.state.predictor = fake_predictor
    return application


@pytest.fixture
def client_factory(app: FastAPI) -> Iterator[Callable[[], TestClient]]:
    """Create independent clients (separate cookie jars) against the same app."""
    clients: list[TestClient] = []

    def make() -> TestClient:
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in reversed(clients):
        client.__exit__(None, None, None)


@pytest.fixture
def client(client_factory: Callable[[], TestClient]) -> TestClient:
    """An anonymous client."""
    return client_factory()


@pytest.fixture
def auth_client(client_factory: Callable[[], TestClient]) -> TestClient:
    """A client logged in as the freshly registered user ``alice``."""
    client = client_factory()
    register_user(client, "alice")
    return client


@pytest.fixture
def other_client(client_factory: Callable[[], TestClient]) -> TestClient:
    """A second logged-in user (``bob``) for ownership isolation tests."""
    client = client_factory()
    register_user(client, "bob")
    return client
