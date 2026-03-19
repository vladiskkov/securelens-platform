"""Container Security Scanner — integrates with Trivy server."""
from dataclasses import dataclass

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger()


@dataclass
class ContainerFinding:
    cve_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: str
    description: str
    cvss_score: float = 0.0


class ContainerScanner:
    """Scans container images via Trivy server API."""

    async def scan_image(self, image: str) -> list[ContainerFinding]:
        """Scan a container image for CVEs."""
        log.info("container_scanner.start", image=image)
        findings = []

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{settings.TRIVY_SERVER_URL}/scan",
                    json={"image": image, "type": "image"},
                )
                resp.raise_for_status()
                data = resp.json()
                findings = self._parse_trivy_results(data)
        except httpx.ConnectError:
            log.warning("container_scanner.trivy_unavailable", image=image)
            # Return mock finding for development
            findings = [ContainerFinding(
                cve_id="TRIVY_UNAVAILABLE",
                severity="INFO",
                package="trivy-server",
                installed_version="N/A",
                fixed_version="N/A",
                description="Trivy server not available. Start with: docker compose up trivy",
            )]
        except Exception as e:
            log.error("container_scanner.error", image=image, error=str(e))

        log.info("container_scanner.complete", image=image, findings=len(findings))
        return findings

    def _parse_trivy_results(self, data: dict) -> list[ContainerFinding]:
        findings = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(ContainerFinding(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    description=vuln.get("Description", "")[:500],
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                ))
        return findings
