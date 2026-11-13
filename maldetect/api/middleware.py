"""ASGI middleware: security response headers and request body size limits."""

from __future__ import annotations

from fastapi import HTTPException
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from maldetect import config

APK_UPLOAD_PATH = "/api/scans/apk"
DOCS_PATH = "/api/docs"

# Multipart framing (boundaries and part headers) sits on top of the file itself.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
# Every other endpoint takes a small JSON document.
JSON_BODY_LIMIT_BYTES = 256 * 1024

# The dashboard is a same-origin static app: scripts only from this origin,
# inline SVG and style attributes for charts, optional Google Fonts.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' data: https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    )
)

# The interactive API docs load their assets from a CDN and bootstrap inline.
DOCS_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "img-src 'self' data: https://fastapi.tiangolo.com",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
    )
)


class SecurityHeadersMiddleware:
    """Attach defensive headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
                headers["Content-Security-Policy"] = (
                    DOCS_CONTENT_SECURITY_POLICY if path == DOCS_PATH else CONTENT_SECURITY_POLICY
                )
                if path.startswith("/api/") and "cache-control" not in headers:
                    # API responses are per-user; keep them out of shared caches.
                    headers["Cache-Control"] = "no-store"
                elif "cache-control" not in headers:
                    # Static assets are unversioned; force revalidation so a deploy
                    # never leaves browsers running stale JS/CSS.
                    headers["Cache-Control"] = "no-cache"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies before they are buffered.

    A declared ``Content-Length`` over the limit is refused up front; bodies
    sent without one (chunked) are counted as they arrive and cut off.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _limit_for(path: str) -> tuple[int, str]:
        if path == APK_UPLOAD_PATH:
            megabytes = config.MAX_UPLOAD_BYTES / (1024 * 1024)
            return (
                config.MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES,
                f"File is too large. The maximum upload size is {megabytes:g} MB.",
            )
        return JSON_BODY_LIMIT_BYTES, "Request body is too large."

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        limit, message = self._limit_for(scope["path"])
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            response = JSONResponse({"detail": message}, status_code=413)
            await response(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            event = await receive()
            if event["type"] == "http.request":
                received += len(event.get("body", b""))
                if received > limit:
                    # Raised inside the endpoint's body read, so the regular
                    # exception handlers turn it into a JSON 413.
                    raise HTTPException(413, message)
            return event

        await self.app(scope, limited_receive, send)
