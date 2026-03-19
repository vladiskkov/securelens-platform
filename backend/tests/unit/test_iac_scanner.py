"""Unit tests for IaC Scanner."""
import pytest
from app.services.scanners.iac_scanner import IaCScanner


TERRAFORM_PUBLIC_S3 = '''
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "public-read"
}
'''

TERRAFORM_PRIVATE_S3 = '''
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "private"
}
'''

TERRAFORM_OPEN_SG = '''
resource "aws_security_group" "test" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def test_detects_public_s3_bucket():
    scanner = IaCScanner()
    findings = scanner.scan_content(TERRAFORM_PUBLIC_S3, "main.tf")
    assert len(findings) == 1
    assert findings[0].rule_id == "SL_TF_S3_001"
    assert findings[0].severity == "HIGH"


def test_no_findings_for_private_s3():
    scanner = IaCScanner()
    findings = scanner.scan_content(TERRAFORM_PRIVATE_S3, "main.tf")
    assert len(findings) == 0


def test_detects_open_security_group():
    scanner = IaCScanner()
    findings = scanner.scan_content(TERRAFORM_OPEN_SG, "main.tf")
    sg_findings = [f for f in findings if f.rule_id == "SL_TF_SG_001"]
    assert len(sg_findings) >= 1
    assert sg_findings[0].severity == "CRITICAL"
