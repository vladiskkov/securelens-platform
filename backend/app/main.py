"""SecureLens Platform — FastAPI Application Entry Point."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes import health, scan, findings
from app.core.config import settings

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("securelens.startup", version=settings.APP_VERSION, env=settings.APP_ENV)
    yield
    log.info("securelens.shutdown")


app = FastAPI(
    title="SecureLens Platform",
    description="Open-source unified cloud security platform",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(scan.router,   prefix="/api/v1/scan",     tags=["scan"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
