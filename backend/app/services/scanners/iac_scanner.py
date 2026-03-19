"""IaC Security Scanner — Terraform, Helm."""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2
import structlog
import yaml

log = structlog.get_logger()

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}


@dataclass
class IaCFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    resource: str
    remediation: str
    line: int = 0
    risk_score: float = 0.0


class IaCScanner:
    """Scans Terraform HCL and Helm charts for security misconfigurations."""

    RULES_PATH = Path(__file__).parent.parent.parent.parent.parent / "rules" / "iac"

    def scan_content(self, content: str, filename: str = "main.tf") -> list[IaCFinding]:
        """Scan raw file content."""
        findings = []
        if filename.endswith(".tf"):
            findings = self._scan_terraform(content)
        elif filename.endswith((".yaml", ".yml")):
            findings = self._scan_helm(content)
        log.info("iac_scanner.complete", filename=filename, findings=len(findings))
        return findings

    def _scan_terraform(self, content: str) -> list[IaCFinding]:
        findings = []
        try:
            parsed = hcl2.loads(content)
        except Exception as e:
            log.warning("iac_scanner.parse_error", error=str(e))
            return findings

        resources = parsed.get("resource", [])
        for resource_block in resources:
            for resource_type, instances in resource_block.items():
                for name, config in instances.items():
                    resource_id = f"{resource_type}.{name}"
                    findings.extend(self._apply_terraform_rules(resource_type, resource_id, config))
        return findings

    def _apply_terraform_rules(self, rtype: str, rid: str, config: dict) -> list[IaCFinding]:
        """Apply CIS benchmark rules to a Terraform resource."""
        findings = []

        # Rule: S3 bucket should not have public ACL
        if rtype == "aws_s3_bucket":
            acl = config.get("acl", ["private"])
            acl_val = acl[0] if isinstance(acl, list) else acl
            if acl_val in ("public-read", "public-read-write", "authenticated-read"):
                findings.append(IaCFinding(
                    rule_id="SL_TF_S3_001",
                    severity="HIGH",
                    title="S3 bucket has public ACL",
                    description=f"Resource {rid} uses ACL '{acl_val}' which grants public access.",
                    resource=rid,
                    remediation='Set acl = "private" and use aws_s3_bucket_public_access_block.',
                    risk_score=8.5,
                ))

        # Rule: Security group should not allow unrestricted inbound
        if rtype == "aws_security_group":
            for ingress in config.get("ingress", []):
                cidr = ingress.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr:
                    findings.append(IaCFinding(
                        rule_id="SL_TF_SG_001",
                        severity="CRITICAL",
                        title="Security group allows unrestricted inbound traffic",
                        description=f"Resource {rid} allows 0.0.0.0/0 inbound.",
                        resource=rid,
                        remediation="Restrict CIDR to known IP ranges.",
                        risk_score=9.5,
                    ))

        # Rule: RDS should not be publicly accessible
        if rtype == "aws_db_instance":
            publicly_accessible = config.get("publicly_accessible", [False])
            if isinstance(publicly_accessible, list):
                publicly_accessible = publicly_accessible[0]
            if publicly_accessible:
                findings.append(IaCFinding(
                    rule_id="SL_TF_RDS_001",
                    severity="HIGH",
                    title="RDS instance is publicly accessible",
                    description=f"Resource {rid} has publicly_accessible = true.",
                    resource=rid,
                    remediation="Set publicly_accessible = false and use VPC.",
                    risk_score=8.0,
                ))

        return findings

    def _scan_helm(self, content: str) -> list[IaCFinding]:
        """Scan Helm chart values/manifests."""
        findings = []
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            return findings

        if not parsed:
            return findings

        # Check for privileged containers
        spec = parsed.get("spec", {})
        containers = spec.get("containers", [])
        for container in containers:
            sc = container.get("securityContext", {})
            if sc.get("privileged"):
                findings.append(IaCFinding(
                    rule_id="SL_HELM_SC_001",
                    severity="CRITICAL",
                    title="Container running as privileged",
                    description=f"Container '{container.get('name')}' has privileged: true.",
                    resource=container.get("name", "unknown"),
                    remediation="Remove privileged: true from securityContext.",
                    risk_score=9.8,
                ))
        return findings
