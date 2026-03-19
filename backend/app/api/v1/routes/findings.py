"""Findings endpoints."""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class Finding(BaseModel):
    id: str
    scan_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # iac, container, asm
    rule_id: str
    title: str
    description: str
    resource: str
    remediation: str
    risk_score: float = 0.0


@router.get("/{scan_id}", summary="Get findings for a scan")
async def get_findings(scan_id: str) -> list[Finding]:
    """Returns all findings for a given scan_id."""
    # TODO: Fetch from PostgreSQL
    return []


@router.get("/", summary="List all findings with filters")
async def list_findings(
    severity: str | None = None,
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Finding]:
    """List all findings with optional severity/category filters."""
    # TODO: Implement with DB query
    return []
