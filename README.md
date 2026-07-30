# CloudShield — Cloud Security Monitoring & Threat Detection Platform

CloudShield is a FastAPI-based security monitoring system that helps users inspect AWS resources, detect common cloud security issues, score account risk, and review findings through a simple API and dashboard.

## Project Goal

The goal of this project is to demonstrate how a lightweight cloud security monitoring application can be built using Python, FastAPI, and AWS SDKs. The system focuses on practical security use cases such as identifying risky configurations, tracking suspicious activity, and surfacing findings in a structured way.

## What the project includes

- User authentication and protected API access
- AWS resource inventory collection using boto3
- CloudTrail-based event analysis
- Security detection rules for common issues
- Risk scoring for security posture evaluation
- Alert and report generation support
- A basic dashboard for interacting with the app
- Automated tests for core functionality

## Status

This project is implemented as a working prototype with a functional backend, API routes, detection logic, and automated tests. AWS integrations require real credentials and permissions to run against a live AWS account.

## Quick start

```bash
cd /home/h3x/project/cloudshield
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION,
# and SECRET_KEY to a random string. Leave AWS creds blank to use your
# default boto3 profile / instance role instead.

uvicorn app.main:app --reload
```

Then open:
- http://127.0.0.1:8000/docs for the interactive API
- http://127.0.0.1:8000/dashboard for the basic dashboard

## Running tests

```bash
pytest tests/ -v
```

## Main API flow

1. Register a user via `POST /api/auth/register`
2. Log in via `POST /api/auth/login`
3. Run a scan via `POST /api/dashboard/scan`
4. Review summary data via `GET /api/dashboard/summary`
5. Review findings via `GET /api/alerts/findings`

## Project structure

```text
cloudshield/
├── app/                  # FastAPI app, routers, services, models, detection logic
├── lambda/               # Lambda-based detection logic
├── terraform/            # Infrastructure as code for real-time workflow
├── tests/                # Automated test suite
├── docs/                 # Architecture and project documentation
└── requirements.txt
```

## Notes for submission

This project is suitable for academic submission because it demonstrates a complete end-to-end implementation of a cloud security monitoring application with backend logic, API design, detection rules, testing, and deployment-related structure.

### Required IAM permissions

The AWS user/role you point this at needs at least read access to:
`ec2:Describe*`, `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetPublicAccessBlock`,
`iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:ListAccessKeys`, `cloudtrail:LookupEvents`.
For the Lambda/EventBridge/SNS real-time path (via Terraform), you'll also need permissions
to create those resources — that's a one-time setup step, not something the app does at runtime.

## Running tests

```bash
pytest tests/ -v
```

19 tests: 5 detection-rule modules (positive + negative cases), the risk-scoring formula
(including the exact 105-risk example from the architecture doc), and a smoke test that
boots the app, creates tables, and runs the register → login → protected-route flow.
None of these touch real AWS — they're safe to run anywhere.

## Using it against your AWS account

1. Set real credentials in `.env` (or leave blank + configure `~/.aws/credentials`).
2. Register a user: `POST /api/auth/register` with a username/password.
3. Log in to get a token, then use it as a Bearer token on everything else.
4. `POST /api/dashboard/scan` — runs a full scan (inventory + CloudTrail + detection +
   alerting) against your real account. This is the main entrypoint.
5. `GET /api/dashboard/summary` — security score + open finding counts.
6. `GET /api/alerts/findings` — the finding list, filterable by `status` / `severity`.
7. `POST /api/reports/generate?report_type=weekly&fmt=pdf` — generates a report file.

For the **real-time** path (EventBridge → Lambda → SNS, instead of polling `/scan`):

```bash
cd lambda && zip -r ../lambda.zip . && cd ..
cd terraform && terraform init && terraform apply -var="alert_email=you@example.com"
```

## Folder structure

```
cloudshield/
├── app/
│   ├── main.py                 # FastAPI app, router wiring, startup DB init
│   ├── config.py                # pydantic-settings, loads .env
│   ├── database.py              # SQLAlchemy engine/session
│   ├── api/                     # auth, aws, dashboard, alerts, reports routers
│   ├── services/                 # auth, aws, monitoring, threat, alert, report services
│   ├── aws/                      # boto3 wrappers: ec2, s3, iam, cloudtrail, sns, eventbridge
│   ├── detection/                 # the 5 rule modules (root_login, public_bucket, ...)
│   ├── models/models.py           # User, ScanHistory, Finding, Alert, Report
│   └── utils/risk_scoring.py       # security score aggregator
├── lambda/                        # standalone real-time detection Lambda
├── terraform/main.tf              # SNS + Lambda + EventBridge IaC
├── tests/                         # 19 tests, all passing
├── docs/architecture.md           # architecture reference
├── Dockerfile / docker-compose.yml
└── requirements.txt
```

## What's stubbed vs. real

- **Real, tested**: all detection logic, risk scoring, auth (JWT + bcrypt), DB models,
  API routing, CSV/PDF report generation, the boto3 wrapper functions themselves.
- **Real but untested-by-me**: every function in `app/aws/*.py` — the boto3 calls are
  correct against the current API, but I haven't run them against a live account. Run
  `POST /api/aws/inventory` first against your account as a sanity check before wiring
  up the full scan.
- **Simplified**: email/SMTP sending isn't implemented in `alert_service.py` yet (SNS and
  console channels are); the Lambda's rule set is a lighter subset of the 5 full rules,
  kept in sync manually rather than importing `app/detection/` directly (Lambda packaging
  favors a small dependency surface — no SQLAlchemy/FastAPI in the zip).

## Next steps (pick what you want built out next)

- Wire email sending into `alert_service.py` (SMTP config is already in `.env.example`)
- Dashboard frontend (currently API-only — `app/templates/` and `app/static/` are empty)
- Scheduled scans via APScheduler (already in requirements.txt, not wired up yet)
- Expand detection rules (e.g. unencrypted EBS volumes, overly permissive IAM policies)
# Cloud-Security-Monitoring_-_Threat-Detection-Platform
