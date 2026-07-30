# How CloudShield Works

CloudShield is a FastAPI-based cloud security monitoring platform. It helps you inspect your AWS environment, detect risky behavior, score your account security posture, and expose the results through a simple API.

## 1. High-level overview

The project has four main responsibilities:

- Collect AWS account information
- Detect security issues from that data
- Score and organize findings
- Expose everything through an API and reports

The app is built around a small web service plus supporting AWS and detection modules.

## 2. Main components

### FastAPI application
The main entrypoint is [app/main.py](app/main.py). It:

- creates the FastAPI app
- includes the API routers
- initializes the database on startup
- exposes basic endpoints like `/` and `/health`

### Authentication
The auth flow lives in [app/api/auth.py](app/api/auth.py) and [app/services/auth_service.py](app/services/auth_service.py).

It allows users to:

- register an account
- log in with a username and password
- receive a JWT access token
- access protected routes with that token

### AWS integration
The AWS logic is split under [app/aws](app/aws) and [app/services/aws_service.py](app/services/aws_service.py).

It uses boto3 to query AWS services such as:

- EC2
- S3
- IAM
- CloudTrail

These services provide the inventory and event data that the detection rules need.

### Detection engine
Detection logic is implemented in [app/detection](app/detection).

The current rules look for common issues such as:

- root login activity
- public S3 buckets
- open security groups
- IAM admin abuse
- access key misuse

Each detector produces a finding with metadata like severity, title, and affected resource.

### Risk scoring
Risk scoring is handled in [app/utils/risk_scoring.py](app/utils/risk_scoring.py).

This module turns the collected findings into a numeric risk score and helps the API surface an overall security posture.

### Alerts and reporting
The alerting and reporting layers are in:

- [app/services/alert_service.py](app/services/alert_service.py)
- [app/services/report_service.py](app/services/report_service.py)
- [app/api/alerts.py](app/api/alerts.py)
- [app/api/reports.py](app/api/reports.py)

These components:

- record alert events
- send alerts through SNS or console output
- allow review of findings
- generate downloadable reports

## 3. How a scan works

A typical flow looks like this:

1. A user authenticates.
2. The app calls AWS APIs to gather account resources and events.
3. Detection rules inspect the collected data.
4. Findings are stored in the database.
5. The dashboard and alerts APIs provide summaries and details.
6. Reports can be generated from the stored findings.

The main entrypoint for a full scan is:

- `POST /api/dashboard/scan`

## 4. Data model

The core database models are defined in [app/models/models.py](app/models/models.py).

Key entities include:

- `User` for authentication
- `ScanHistory` for scan runs
- `Finding` for detected issues
- `Alert` for alert delivery results
- `Report` for generated reports

## 5. How the app is started

Start the service with:

```bash
cd /home/h3x/project/cloudshield
source .venv/bin/activate
uvicorn app.main:app --reload
```

Then open:

- `/` for a simple status page
- `/health` for health check output
- `/docs` for interactive Swagger documentation

## 6. How the project is organized

- [app/api](app/api) contains API routes
- [app/services](app/services) contains business logic
- [app/aws](app/aws) contains AWS SDK wrapper code
- [app/detection](app/detection) contains detection rules
- [app/models](app/models) defines the database models
- [tests](tests) contains automated tests for the app

## 7. What this project is good for

CloudShield is useful for:

- learning how to build a security monitoring app with FastAPI
- testing detection logic against AWS resources
- exploring how findings, scoring, and alerts can work together
- building a simple internal security dashboard API

## 8. Important note

The AWS parts are real boto3 integrations, so they require real AWS credentials and permissions to work against a live account. The local tests do not require AWS access.
