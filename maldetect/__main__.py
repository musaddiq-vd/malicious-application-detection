"""Run the web application: ``python -m maldetect``.

Host and port come from ``MALDETECT_HOST`` / ``MALDETECT_PORT`` and default to
a loopback-only server on http://127.0.0.1:8000.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("MALDETECT_HOST", "127.0.0.1")
    port = int(os.environ.get("MALDETECT_PORT", "8000"))
    uvicorn.run("maldetect.api.app:app", host=host, port=port)


if __name__ == "__main__":
    main()
