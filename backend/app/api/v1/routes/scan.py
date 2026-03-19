"""Scan endpoints — IaC, Container, ASM."""
import uuid
from enum import Enum

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File
from pydantic import BaseModel

from app.services.scanners.iac_scanner import IaCScanner
from app.services.scanners.container_scanner import ContainerScanner

router = APIRouter()


class ScanType(str, Enum):
    iac = "iac"
    container = "container"
    asm = "asm"
    full = "full"


class ScanRequest(BaseModel):
    scan_type: ScanType
    target: str  # repo URL, image name, or domain
    options: dict = {}


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@router.post("/iac", response_model=ScanResponse, summary="Scan IaC files (Terraform, Helm)")
async def scan_iac(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    """
    Upload Terraform (.tf) or Helm chart (zip) for security analysis.
    Returns a scan_id to track results via GET /findings/{scan_id}
    """
    scan_id = str(uuid.uuid4())
    content = await file.read()

    # TODO: background_tasks.add_task(IaCScanner().scan, scan_id, content, file.filename)
    scanner = IaCScanner()
    findings = scanner.scan_content(content.decode(), filename=file.filename)

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        message=f"Found {len(findings)} findings",
    )


@router.post("/container", response_model=ScanResponse, summary="Scan container image")
async def scan_container(request: ScanRequest):
    """
    Scan a container image for CVEs and misconfigurations.
    Target should be a valid image reference (e.g. nginx:1.25, ghcr.io/org/app:latest)
    """
    scan_id = str(uuid.uuid4())
    scanner = ContainerScanner()
    findings = await scanner.scan_image(request.target)

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        message=f"Found {len(findings)} CVEs",
    )
