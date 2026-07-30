# CloudShield — Architecture Reference

This is the original architecture this project was built from, kept here for reference.

## Components

- **FastAPI Web Application** — single entrypoint (`app/main.py`), routing to five service areas:
  Authentication, Dashboard, Detection Engine, Report Service, Alert Service.
- **Persistence** — SQLAlchemy ORM over SQLite (dev) or PostgreSQL (prod, via docker-compose).
- **AWS Cloud Environment** — IAM, CloudTrail, EventBridge, Lambda, SNS, EC2, S3, VPC, Security Groups.

## Data flow

1. CloudTrail records account activity (root logins, IAM changes, resource deletions, etc).
2. Two parallel paths consume this:
   - **Real-time**: EventBridge rule matches watched event names → invokes the CloudShield
     Lambda (`lambda/lambda_function.py`) → publishes to SNS on a match.
   - **On-demand / periodic**: `POST /api/dashboard/scan` pulls a full resource inventory
     (EC2, S3, IAM, Security Groups) plus recent CloudTrail events, runs all five detection
     rules, persists findings, and dispatches alerts for HIGH/CRITICAL findings.
3. Findings feed the risk scoring engine (`app/utils/risk_scoring.py`), which produces a
   0–100 security score for the dashboard.

## Detection rules → risk points

| Rule | Trigger | Severity | Risk points |
|---|---|---|---|
| `ROOT_LOGIN` | Root account console login | CRITICAL | 40 |
| `OPEN_SECURITY_GROUP` | 0.0.0.0/0 on SSH/RDP/DB ports | HIGH | 30 |
| `PUBLIC_S3_BUCKET` | Bucket publicly accessible | MEDIUM | 20 |
| `IAM_ADMIN_USER` | User has AdministratorAccess | CRITICAL | 40 |
| `STALE_ACCESS_KEY` | Active key older than 90 days | LOW | 15 |

Score = `max(0, 100 - total_risk)`. Bands: 90+ Excellent, 70+ Good, 40+ Warning, below Critical.

## Folder structure

See the root `README.md` for the annotated folder tree and setup instructions.
