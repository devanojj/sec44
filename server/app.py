from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from sqlalchemy.exc import SQLAlchemyError

from server.api_v1 import router as api_v1_router
from server.auth import AuthManager
from server.auth_routes import router as auth_router
from server.cache import RedisCache, RedisRateLimiter
from server.config import ServerConfig, load_config
from server.dashboard import router as dashboard_router
from server.db import ServerDatabase
from server.ingest import router as ingest_router
from server.security import EnforceHTTPSMiddleware, SecurityHeadersMiddleware
from server.telemetry import router as telemetry_router
logger = logging.getLogger("endpoint_server.app")


def create_app(config: ServerConfig | None = None) -> FastAPI:
    cfg = config or load_config()

    app = FastAPI(
        title="Insight-first Endpoint Monitor",
        docs_url="/docs" if cfg.dev_enable_docs else None,
        redoc_url="/redoc" if cfg.dev_enable_docs else None,
        openapi_url="/openapi.json" if cfg.dev_enable_docs else None,
    )

    db = ServerDatabase(cfg.database_url)
    if cfg.database_url.lower().startswith("sqlite://"):
        db.init_for_tests()
    auth = AuthManager(cfg)
    cache = RedisCache(cfg.redis_url)
    limiter = RedisRateLimiter(cfg.redis_url, fail_closed=cfg.environment not in {"test", "ci"})

    templates_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app.state.config = cfg
    app.state.db = db
    app.state.auth = auth
    app.state.cache = cache
    app.state.rate_limiter = limiter
    app.state.templates = Jinja2Templates(directory=str(templates_dir))
    app.state.templates.env.autoescape = select_autoescape(enabled_extensions=("html", "xml"), default=True)
    app.state.signing_keys = {org.org_id: org.api_key for org in cfg.org_seeds}

    app.add_middleware(EnforceHTTPSMiddleware, enabled=cfg.enforce_https)
    app.add_middleware(SecurityHeadersMiddleware)

    from server.telemetry import MetricsMiddleware

    app.add_middleware(MetricsMiddleware)

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(ingest_router)
    app.include_router(auth_router)
    app.include_router(api_v1_router)
    app.include_router(dashboard_router)
    app.include_router(telemetry_router)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        try:
            cache.ping()
            db.ping()
        except SQLAlchemyError as exc:
            return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc.__class__.__name__)})
        except Exception as exc:
            return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc.__class__.__name__)})
        return JSONResponse(content={"status": "ok"})

    @app.on_event("startup")
    async def _startup() -> None:
        try:
            cache.ping()
        except Exception:
            logger.exception("redis connection failed at startup")
        db.seed_orgs(cfg.org_seeds)
        db.seed_users(cfg.user_seeds, auth.hash_password)

    return app


try:
    app = create_app()
except Exception:
    logger.exception("failed to create default app; configure environment variables before startup")
    app = FastAPI()
