"""Serve only the trusted production entry point and its assets, alongside API routes."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles


def mount_web(application: FastAPI, directory: Path | None) -> None:
    if directory is None:
        return
    directory = directory.resolve()
    index = directory / "index.html"
    if not index.is_file() or not (directory / "assets").is_dir():
        raise ValueError("WEB_BUILD_UNAVAILABLE")

    @application.get("/", include_in_schema=False)
    def entry() -> FileResponse:
        return FileResponse(
            index,
            headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
        )

    application.mount("/assets", StaticFiles(directory=directory / "assets"), name="web-assets")
