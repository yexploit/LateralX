"""LateralX FastAPI application entrypoint."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.routes import router
from app.config import get_settings
from app.db import event_count, init_db, load_events
from app.engine.pipeline import empty_pipeline, run_pipeline
from app.store import store


def _resolve_web_dir() -> Path | None:
    env = os.getenv("LATERALX_STATIC_DIR")
    candidates = []
    if env:
        candidates.append(Path(env))
    here = Path(__file__).resolve().parent
    candidates.append(here / "web")
    candidates.append(here.parent.parent / "frontend" / "dist")
    for path in candidates:
        if path.is_dir() and (path / "index.html").exists():
            return path
    return None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    init_db()
    existing = load_events()
    if existing:
        run_pipeline(store, existing)
    elif settings.seed_on_startup:
        from app.engine.synthetic import generate_scenario_events
        from app.db import save_events
        from app.engine.enricher import enrich_events

        events = enrich_events(generate_scenario_events())
        save_events(events, source_file="seed:synthetic")
        run_pipeline(store, events)
    else:
        empty_pipeline(store)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description=(
            "Cross-host lateral movement detection and attack-path investigation. "
            "Ingest Windows EVTX / Sysmon XML / JSON / CSV, correlate, and investigate."
        ),
        version=__version__,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins + ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix="/api")

    web_dir = _resolve_web_dir()

    if web_dir is None:

        @app.get("/")
        def root():
            return {
                "name": settings.app_name,
                "version": __version__,
                "docs": "/docs",
                "health": "/api/health",
                "events_in_db": event_count(),
            }

        return app

    assets = web_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/")
    def index():
        return FileResponse(web_dir / "index.html")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str):
        reserved = ("api", "docs", "redoc", "openapi.json")
        if full_path == "api" or full_path.startswith("api/") or full_path in reserved:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Not found")
        candidate = web_dir / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(web_dir / "index.html")

    return app


app = create_app()
