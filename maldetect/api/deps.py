"""Shared FastAPI dependencies: database, current user and the loaded model."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Annotated, Any, Protocol

from fastapi import Depends, HTTPException, Request, status

from maldetect.api import security, store
from maldetect.api.db import get_db

MODEL_UNAVAILABLE = (
    "The detection model is not available. Train it first with: python -m maldetect.ml.train"
)


class PredictorLike(Protocol):
    """The slice of ``maldetect.ml.predictor.Predictor`` the API relies on."""

    def predict(self, features: Mapping[str, int]) -> Any: ...


Database = Annotated[sqlite3.Connection, Depends(get_db)]


def get_current_user(request: Request, conn: Database) -> dict[str, Any]:
    token = request.cookies.get(security.SESSION_COOKIE)
    user = store.get_session_user(conn, token) if token else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]


def get_predictor(request: Request) -> PredictorLike:
    predictor = getattr(request.app.state, "predictor", None)
    if predictor is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, MODEL_UNAVAILABLE)
    return predictor


ModelPredictor = Annotated[PredictorLike, Depends(get_predictor)]
