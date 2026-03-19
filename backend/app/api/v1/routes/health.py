"""Health check endpoints."""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    services: dict[str, str]


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Returns platform health status."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
        services={
            "api": "ok",
            "database": "ok",
            "graph": "ok",
            "queue": "ok",
        },
    )
