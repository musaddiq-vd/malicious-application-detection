"""Health, feature catalog, presets and model metrics."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

import maldetect
from maldetect import config
from maldetect import features as catalog
from maldetect.api.deps import CurrentUser
from maldetect.api.presets import build_presets
from maldetect.api.schemas import Health

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/health", response_model=Health)
def health(request: Request) -> dict[str, Any]:
    return {
        "status": "ok",
        "model_loaded": getattr(request.app.state, "predictor", None) is not None,
        "version": maldetect.__version__,
    }


@router.get("/features")
def list_features(user: CurrentUser) -> dict[str, Any]:
    return {
        "features": [
            {
                "slug": feature.slug,
                "label": feature.label,
                "category": feature.category,
                "description": feature.description,
            }
            for feature in catalog.FEATURES
        ],
        "categories": dict(catalog.CATEGORIES),
    }


@router.get("/features/presets")
def list_presets(user: CurrentUser) -> dict[str, Any]:
    return {"presets": list(build_presets())}


@router.get("/model/metrics")
def model_metrics(user: CurrentUser) -> JSONResponse:
    try:
        metrics = json.loads(config.METRICS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Model metrics are not available. Train the model first with: "
            "python -m maldetect.ml.train",
        ) from exc
    return JSONResponse(metrics)
