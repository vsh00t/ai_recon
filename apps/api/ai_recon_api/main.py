"""FastAPI app entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ai_recon_api import __version__
from ai_recon_api.bootstrap import ensure_admin
from ai_recon_api.db.init import init_db
from ai_recon_api.logging import configure_logging, get_logger
from ai_recon_api.routers import (
    adapters,
    auth,
    catalogs,
    profiles,
    reports,
    runs,
    scopes,
    system,
)
from ai_recon_api.settings import get_settings
from ai_recon_api.ws import runs as ws_runs

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    await init_db()
    await ensure_admin()
    logger.info("api_started", version=__version__)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ai-recon API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_prefix = "/api/v1"
    app.include_router(system.router, prefix=api_prefix)
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(techniques_router(), prefix=api_prefix)
    app.include_router(catalogs.router, prefix=api_prefix)
    app.include_router(profiles.router, prefix=api_prefix)
    app.include_router(adapters.router, prefix=api_prefix)
    app.include_router(scopes.router, prefix=api_prefix)
    app.include_router(runs.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(ws_runs.router)

    return app


def techniques_router():
    from ai_recon_api.routers import techniques as t

    return t.router


app = create_app()
