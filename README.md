<div align="center">
  <h1>🛡️ SecureLens Platform</h1>
  <p>Open-source unified cloud security platform combining IaC scanning,<br>Container security and Attack Surface Management in one risk graph.</p>

  ![License](https://img.shields.io/badge/license-Apache%202.0-blue)
  ![Python](https://img.shields.io/badge/python-3.12+-green)
  ![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-teal)
  ![Status](https://img.shields.io/badge/status-alpha-orange)
</div>

---

## Why SecureLens?

| Tool | Does | Missing |
|------|------|---------|
| Checkov / tfsec | IaC static analysis | No container + ASM context |
| Trivy / Grype | Container CVE scan | No IaC correlation |
| Shodan / Amass | External recon | No internal mapping |
| Wiz / Orca | Everything | $500k+/yr, closed source |

**SecureLens** = open-source alternative combining all three with a **risk correlation graph**.

## Features

- **IaC Engine** — Terraform, Helm, CDK misconfiguration detection (CIS Benchmarks)
- **Container Engine** — Docker image CVE scan, K8s manifest audit, SBOM generation
- **Risk Graph** — Neo4j-powered correlation: IaC resource → CVE → exposed endpoint
- **ASM Engine** — Subdomain enum, open ports, cert transparency, external surface mapping
- **CI/CD Hooks** — GitHub/GitLab webhooks, PR annotations with findings
- **Policy-as-Code** — Custom rules via OPA/Rego
- **Compliance Reports** — SOC2, ISO27001, PCI-DSS auto-mapping (Enterprise)

## Quick Start

```bash
# Clone & start
git clone https://github.com/YOUR_USERNAME/securelens-platform.git
cd securelens-platform
cp .env.example .env
docker compose up -d

# API is now available at http://localhost:8000
# Dashboard at http://localhost:3000
```

## Architecture

```
┌─ Integrations: GitHub · GitLab · Jira · Slack ─────────────┐
├─ Scan Engines ──────────────────────────────────────────────┤
│  IaC Engine     │  Container Engine  │  ASM Engine          │
├─ Risk Correlation Graph (Neo4j) ────────────────────────────┤
│  Policy Engine  │  Identity & RBAC                          │
├─ Dashboard · REST API · CI/CD · Compliance Reports ─────────┤
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python 3.12, FastAPI, Celery |
| Frontend | React 18, TypeScript, Tailwind CSS |
| Primary DB | PostgreSQL 16 |
| Risk Graph | Neo4j 5 |
| Queue/Cache | Redis 7 |
| Scanner | Trivy (embedded), custom HCL parser |
| Policy | OPA / Rego |
| Deploy | Docker Compose → Helm chart |

## Development

```bash
# Backend dev
cd backend
pip install -r requirements-dev.txt
uvicorn app.main:app --reload

# Run tests
pytest tests/
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed setup.

## Roadmap

- [x] Project bootstrap
- [ ] **Phase 1**: IaC scanner + Container scan + Dashboard (months 1–3)
- [ ] **Phase 2**: Risk graph + CI/CD hooks (months 4–5)
- [ ] **Phase 3**: ASM module + Community launch (months 6–8)
- [ ] **Phase 4**: Enterprise (SSO, compliance, SaaS) (year 2)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](./LICENSE)
