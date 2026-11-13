"""Application factory.

``create_app()`` wires storage, the model, middleware, error handling, the API
routers and the static single-page dashboard. ``app`` is the instance uvicorn
serves (``python -m maldetect``).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response

import maldetect
from maldetect import config
from maldetect.api import db
from maldetect.api.middleware import DOCS_PATH, BodySizeLimitMiddleware, SecurityHeadersMiddleware
from maldetect.api.presets import build_presets
from maldetect.api.routers import auth, meta, scans
from maldetect.api.security import LoginRateLimiter

logger = logging.getLogger("maldetect.api")

_REQUEST_PARTS = {"body", "query", "path", "header", "cookie"}


def load_predictor() -> Any | None:
    """Load the trained model, or return ``None`` so the app can still start."""
    try:
        from maldetect.ml.predictor import Predictor

        return Predictor.load()
    except FileNotFoundError:
        logger.warning(
            "No trained model found at %s. Scan endpoints will return 503 until you run: "
            "python -m maldetect.ml.train",
            config.MODEL_PATH,
        )
    except Exception:
        logger.exception("Failed to load the model at %s", config.MODEL_PATH)
    return None


def _flatten_validation_errors(exc: RequestValidationError) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for error in exc.errors():
        location = [str(part) for part in error.get("loc", ())]
        if location and location[0] in _REQUEST_PARTS:
            location = location[1:]
        field = ".".join(location) or "body"
        message = str(error.get("msg", "Invalid value"))
        if error.get("type") == "missing":
            message = f"{field} is required"
        elif message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        errors.append({"field": field, "message": message})
    return errors


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = _flatten_validation_errors(exc)
    detail = errors[0]["message"] if errors else "Invalid request"
    return JSONResponse({"detail": detail, "errors": errors}, status_code=422)


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        {"detail": "Internal server error"}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def _resolve_static(web_dir: Path, relative: str) -> Path | None:
    """Map a URL path to a file inside ``web_dir``, refusing anything outside it."""
    root = web_dir.resolve()
    candidate = (root / relative).resolve()
    if candidate.is_relative_to(root) and candidate.is_file():
        return candidate
    return None


def _register_spa(app: FastAPI) -> None:
    @app.api_route(
        "/api/{rest:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    def api_not_found(rest: str) -> Response:
        # Keeps unknown API paths from falling through to the dashboard HTML.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> Response:
        web_dir = config.WEB_DIR
        if full_path:
            asset = _resolve_static(web_dir, full_path)
            if asset is not None:
                return FileResponse(asset)
            if "." in full_path.rsplit("/", 1)[-1]:
                # A missing asset must not be answered with HTML.
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        index = _resolve_static(web_dir, "index.html")
        if index is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "The web dashboard is not installed (web/index.html)"
            )
        # Client-side routes all resolve to the app shell, which must stay fresh.
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


def create_app(*, load_model: bool = True) -> FastAPI:
    """Build the application.

    ``load_model=False`` skips reading the model from disk at startup; callers
    (tests) can then place their own predictor on ``app.state.predictor``.
    """
    build_presets()  # Fail fast if a preset drifted from the feature catalog.

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db.init_db()
        if load_model:
            app.state.predictor = load_predictor()
        yield

    app = FastAPI(
        title="MalDetect API",
        description="Android malware detection with explainable predictions.",
        version=maldetect.__version__,
        lifespan=lifespan,
        docs_url=DOCS_PATH,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.predictor = None
    app.state.login_limiter = LoginRateLimiter()

    # Added last = outermost, so security headers also cover early 413 replies.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)

    app.include_router(meta.router)
    app.include_router(auth.router)
    app.include_router(scans.router)
    _register_spa(app)
    return app


app = create_app()
