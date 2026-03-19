# Contributing to SecureLens Platform

Thank you for your interest in contributing!

## Getting Started

### Prerequisites
- Python 3.12+
- Docker & Docker Compose
- Node.js 20+ (frontend)
- `make` (optional but recommended)

### Local Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/securelens-platform.git
cd securelens-platform

# 2. Create a branch
git checkout -b feature/your-feature-name

# 3. Start dependencies
docker compose up -d postgres redis neo4j

# 4. Setup backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example ../.env
uvicorn app.main:app --reload

# 5. Run tests
pytest tests/ -v
```

## Project Structure

```
securelens-platform/
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── api/v1/routes/   # API endpoints
│   │   ├── core/            # Config, security
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── services/        # Business logic
│   │   └── graph/           # Neo4j graph operations
│   └── tests/
├── frontend/                # React application
├── rules/                   # Security rules (IaC, container, ASM)
├── docs/                    # Documentation
└── deploy/                  # Docker + Helm configs
```

## Contribution Guidelines

- Follow [Conventional Commits](https://www.conventionalcommits.org/)
- Write tests for new features (aim for 80%+ coverage)
- Update docs when adding new functionality
- One feature/fix per PR

## Adding Security Rules

Rules live in `/rules/`. YAML format:

```yaml
id: TF_S3_001
name: S3 bucket public access
severity: HIGH
resource: aws_s3_bucket
check: public_access_block.block_public_acls == true
remediation: "Add aws_s3_bucket_public_access_block resource"
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
```

## Code of Conduct

Be respectful. Be constructive. Help others learn.
