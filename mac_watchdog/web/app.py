from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.web.middleware import SecurityHeadersMiddleware
from mac_watchdog.web.routes import router


def create_app(config: AppConfig, db: Database) -> FastAPI:
    docs_enabled = bool(config.dev_enable_docs)

    app = FastAPI(
        title="Mac Security Watchdog",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    templates_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app.state.config = config
    app.state.db = db
    app.state.templates = Jinja2Templates(directory=str(templates_dir))

    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.include_router(router)

    return app
