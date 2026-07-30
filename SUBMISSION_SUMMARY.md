# CloudShield Submission Summary

## Project Title
CloudShield — Cloud Security Monitoring & Threat Detection Platform

## Objective
Build a cloud security monitoring system that can inspect AWS resources, detect security misconfigurations, score account risk, and present security findings through an API.

## What was implemented
- FastAPI-based web API
- User authentication and JWT-based access control
- AWS resource inventory collection using boto3
- CloudTrail event analysis
- Security detection rules for common issues
- Risk scoring for security posture evaluation
- Alert and report generation support
- A simple dashboard page for basic interaction
- Automated tests for core behavior

## Key Features
- Register and log in users
- Run security scans against AWS resources
- View security summaries and findings
- Review detected issues and their severity
- Generate reports for analysis

## Technologies Used
- Python
- FastAPI
- SQLAlchemy
- Pydantic
- boto3
- pytest
- JWT / bcrypt

## How to Run
```bash
cd /home/h3x/project/cloudshield
source .venv/bin/activate
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/dashboard

## Notes
The AWS integrations require real AWS credentials and permissions to work against a live account. The core app and tests can still be run locally without AWS access.
