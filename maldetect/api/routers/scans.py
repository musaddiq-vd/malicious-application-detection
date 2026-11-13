"""Scan creation (manual and APK upload), history and dashboard statistics."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile, status

from maldetect import config
from maldetect import features as catalog
from maldetect.api import store
from maldetect.api.deps import CurrentUser, Database, ModelPredictor, PredictorLike
from maldetect.api.schemas import (
    MAX_APP_NAME_LENGTH,
    ManualScanRequest,
    Scan,
    ScanPage,
    Stats,
    clean_text,
)
from maldetect.ml.apk import ApkParseError, analyze_apk

router = APIRouter(prefix="/api", tags=["scans"])

DEFAULT_MANUAL_NAME = "Manual scan"
DEFAULT_UPLOAD_NAME = "upload.apk"
_CHUNK_BYTES = 1024 * 1024
SCAN_NOT_FOUND = "Scan not found"


def upload_too_large_message() -> str:
    megabytes = config.MAX_UPLOAD_BYTES / (1024 * 1024)
    return f"File is too large. The maximum upload size is {megabytes:g} MB."


def sanitize_filename(filename: str | None) -> str:
    """Reduce a client-supplied filename to a safe display name.

    The name is only ever stored and shown, never used as a filesystem path,
    but directory components and control characters are stripped anyway.
    """
    name = re.split(r"[\\/]", filename or "")[-1]
    name = clean_text(name)[:MAX_APP_NAME_LENGTH].strip()
    return name or DEFAULT_UPLOAD_NAME


def _full_vector(submitted: dict[str, int]) -> dict[str, int]:
    """Expand a partial submission to all catalog features (missing means 0)."""
    return {slug: int(submitted.get(slug, 0)) for slug in catalog.slugs()}


def _predict(predictor: PredictorLike, features: dict[str, int]) -> dict[str, Any]:
    try:
        return store.prediction_to_dict(predictor.predict(features))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/scans/manual", response_model=Scan, status_code=status.HTTP_201_CREATED)
def create_manual_scan(
    payload: ManualScanRequest, user: CurrentUser, predictor: ModelPredictor, conn: Database
) -> dict[str, Any]:
    features = _full_vector(payload.features)
    return store.create_scan(
        conn,
        user_id=user["id"],
        app_name=payload.app_name or DEFAULT_MANUAL_NAME,
        source="manual",
        features=features,
        prediction=_predict(predictor, features),
    )


@router.post("/scans/apk", response_model=Scan, status_code=status.HTTP_201_CREATED)
def create_apk_scan(
    file: Annotated[UploadFile, File(description="Android application package (.apk)")],
    user: CurrentUser,
    predictor: ModelPredictor,
    conn: Database,
) -> dict[str, Any]:
    limit = config.MAX_UPLOAD_BYTES
    handle, temp_name = tempfile.mkstemp(prefix="maldetect-", suffix=".apk")
    temp_path = Path(temp_name)
    try:
        size = 0
        with os.fdopen(handle, "wb") as out:
            while chunk := file.file.read(_CHUNK_BYTES):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, upload_too_large_message())
                out.write(chunk)
        if size == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "The uploaded file is empty")
        try:
            report = analyze_apk(temp_path)
        except ApkParseError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"Not a valid APK file: {exc}"
            ) from exc
    finally:
        temp_path.unlink(missing_ok=True)

    features = _full_vector(dict(report.features))
    apk = {
        "package": report.package,
        "sha256": report.sha256,
        "size_bytes": int(report.size_bytes),
        "dex_count": int(report.dex_count),
        "permissions": list(report.permissions),
        "evidence": dict(report.evidence),
    }
    return store.create_scan(
        conn,
        user_id=user["id"],
        app_name=sanitize_filename(file.filename),
        source="apk",
        features=features,
        prediction=_predict(predictor, features),
        apk=apk,
    )


@router.get("/scans", response_model=ScanPage)
def list_scans(
    user: CurrentUser,
    conn: Database,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    verdict: Literal["malicious", "benign"] | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> dict[str, Any]:
    items, total = store.list_scans(
        conn, user["id"], limit=limit, offset=offset, verdict=verdict, query=(q or "").strip()
    )
    return {"items": items, "total": total}


@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, user: CurrentUser, conn: Database) -> dict[str, Any]:
    scan = store.get_scan(conn, user["id"], scan_id)
    if scan is None:
        # 404 rather than 403: do not reveal that another user's scan exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, SCAN_NOT_FOUND)
    return scan


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, user: CurrentUser, conn: Database) -> Response:
    if not store.delete_scan(conn, user["id"], scan_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, SCAN_NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/stats", response_model=Stats)
def stats(user: CurrentUser, conn: Database) -> dict[str, Any]:
    return store.compute_stats(conn, user["id"])
