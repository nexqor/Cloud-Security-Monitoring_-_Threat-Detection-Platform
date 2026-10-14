# 🛡️ CloudShield – Cloud Security Monitoring & Threat Detection Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg">
  <img src="https://img.shields.io/badge/FastAPI-Framework-green.svg">
  <img src="https://img.shields.io/badge/AWS-Boto3-orange.svg">
  <img src="https://img.shields.io/badge/Terraform-IaC-purple.svg">
  <img src="https://img.shields.io/badge/Docker-Container-blue.svg">
  <img src="https://img.shields.io/badge/License-MIT-success.svg">
</p>

---

# 📖 Overview

**CloudShield** is a Cloud Security Monitoring and Threat Detection Platform developed using **Python**, **FastAPI**, **AWS**, and **Terraform**.

The project continuously monitors AWS resources, detects common cloud security vulnerabilities, analyzes CloudTrail events, calculates an overall security risk score, and generates security reports through REST APIs.

CloudShield demonstrates the practical implementation of cloud security automation and modern backend development techniques. It simulates the basic functionality of Cloud Security Posture Management (CSPM) solutions used in enterprise environments.

---

# 🎯 Project Objectives

The main objectives of this project are:-

- Monitor AWS cloud resources automatically.
- Detect common cloud security threats.
- Analyze CloudTrail logs.
- Identify insecure AWS configurations.
- Calculate security risk score.
- Generate alerts and reports.
- Demonstrate Infrastructure as Code using Terraform.
- Showcase AWS Lambda integration.
- Develop secure REST APIs using FastAPI.
- Apply software engineering best practices.

---

# ❗ Problem Statement

Cloud environments change rapidly, making manual security monitoring difficult. Misconfigured S3 buckets, overly permissive Security Groups, root account usage, and insecure IAM permissions can expose organizations to security risks.

CloudShield automates the monitoring process by collecting AWS resource information, applying security detection rules, generating findings, calculating risk scores, and presenting security insights through APIs.

---

# ✨ Features

## Authentication

- User Registration
- User Login
- JWT Authentication
- Password Encryption using BCrypt

---

## AWS Monitoring

Supports monitoring of:

- Amazon EC2
- Amazon S3
- AWS IAM
- AWS CloudTrail

---

## Security Detection Rules

CloudShield currently detects:

- Root Account Login
- Public S3 Buckets
- Open Security Groups
- IAM Administrator Accounts
- Old Access Keys

---

## Reporting

- PDF Reports
- CSV Reports
- Weekly Reports
- Monthly Reports

---

## Risk Scoring

The application calculates an overall security score depending upon:

- Critical Findings
- High Findings
- Medium Findings
- Low Findings

---

## Infrastructure as Code

Terraform automatically creates:

- SNS Topic
- EventBridge Rule
- Lambda Trigger

---

## Automated Testing

Includes automated testing using **Pytest**.

---

# 🏗 Technology Stack

## Programming Language

- Python 3.9+

## Backend

- FastAPI

## Database

- SQLite
- SQLAlchemy ORM

## Authentication

- JWT
- BCrypt

## AWS Services

- EC2
- S3
- IAM
- CloudTrail
- SNS
- Lambda
- EventBridge

## Infrastructure

- Terraform

## Containerization

- Docker
- Docker Compose

## Testing

- Pytest

---

# 🏛 System Architecture

```
                     User
                       │
                       │
                FastAPI Backend
                       │
       ┌───────────────┼───────────────┐
       │               │               │
 Authentication   Dashboard      Reports
       │               │               │
       └───────────────┼───────────────┘
                       │
               Monitoring Service
                       │
             Threat Detection Engine
                       │
 ┌──────────┬──────────┬──────────┬──────────┐
 │          │          │          │          │
EC2         S3        IAM   CloudTrail   Risk Engine
                       │
                AWS Cloud Account
                       │
           Findings + Security Score
                       │
        PDF Reports / CSV Reports / Alerts
```

---

# 🔄 Project Workflow

1. User registers.
2. User logs in.
3. JWT token is generated.
4. User initiates cloud scan.
5. AWS resources are collected.
6. Detection rules are executed.
7. Findings are generated.
8. Risk score is calculated.
9. Reports are generated.
10. Dashboard displays security posture.

---

# 📁 Project Structure

```text
cloudshield/
│
├── app/
│   ├── api/                   # REST API routes
│   ├── aws/                   # AWS integrations
│   ├── detection/             # Security detection rules
│   ├── services/              # Business logic
│   ├── models/                # Database models
│   ├── utils/                 # Utility functions
│   ├── templates/             # HTML templates
│   ├── static/                # Static resources
│   ├── config.py
│   ├── database.py
│   └── main.py
│
├── lambda/                    # Lambda functions
│
├── terraform/                 # Infrastructure as Code
│
├── docs/                      # Documentation
│
├── generated_reports/         # Generated reports
│
├── tests/                     # Automated tests
│
├── Dockerfile
├── docker-compose.yml
├── HOW_IT_WORKS.md
├── SUBMISSION_SUMMARY.md
├── README.md
├── requirements.txt
└── cloudshield.db
```

---

# 📦 Installation

## Clone Repository

```bash
git clone https://github.com/manishkumar0607/Cloud-Security-Monitoring_-_Threat-Detection-Platform.git

cd cloudshield
```

---

## Create Virtual Environment

Linux

```bash
python -m venv .venv

source .venv/bin/activate
```

Windows

```bash
python -m venv .venv

.venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Environment

Copy

```bash
cp .env.example .env
```

Configure

```
AWS_ACCESS_KEY_ID=

AWS_SECRET_ACCESS_KEY=

AWS_REGION=

SECRET_KEY=
```

---

# ▶ Run Application

```bash
uvicorn app.main:app --reload
```

Open:

```
http://127.0.0.1:8000/docs
```

Swagger API Documentation

```
http://127.0.0.1:8000/dashboard
```

Dashboard

---

# 🧪 Running Tests

Run

```bash
pytest tests/ -v
```

The project contains automated tests for:

- Authentication
- Detection Rules
- Risk Scoring
- Database
- API Endpoints

---

# 🔐 Detection Rules

## Root Login Detection

Detects AWS Root Account logins.

Severity: **Critical**

---

## Public Bucket Detection

Detects publicly accessible S3 buckets.

Severity: **High**

---

## Open Security Group

Detects unrestricted inbound traffic.

Severity: **High**

---

## IAM Administrator Detection

Detects IAM users with AdministratorAccess policy.

Severity: **Medium**

---

## Access Key Detection

Detects old IAM Access Keys.

Severity: **Medium**

---

# 📊 Risk Scoring

Example scoring:

| Severity | Weight |
|----------|---------|
| Critical | 50 |
| High | 25 |
| Medium | 15 |
| Low | 5 |

The overall security score represents the cloud security posture.

---

# 📡 API Endpoints

## Authentication

```
POST /api/auth/register
```

```
POST /api/auth/login
```

---

## Dashboard

```
POST /api/dashboard/scan
```

```
GET /api/dashboard/summary
```

---

## Alerts

```
GET /api/alerts/findings
```

---

## Reports

```
POST /api/reports/generate
```

---

## AWS Inventory

```
POST /api/aws/inventory
```

---

# ☁ AWS Services Used

| Service | Purpose |
|----------|----------|
| EC2 | Instance Monitoring |
| S3 | Bucket Security |
| IAM | Identity Monitoring |
| CloudTrail | Event Monitoring |
| SNS | Notifications |
| Lambda | Serverless Detection |
| EventBridge | Event Trigger |

---

# 🐳 Docker

Build

```bash
docker build -t cloudshield .
```

Run

```bash
docker-compose up
```

---

# 🌍 Terraform

Initialize

```bash
terraform init
```

Apply

```bash
terraform apply
```

Terraform provisions:

- SNS Topic
- EventBridge Rule
- Lambda Trigger

---

# 📈 Future Enhancements

- Email Notifications
- AWS Config Integration
- GuardDuty Integration
- Security Hub Integration
- CloudWatch Monitoring
- Kubernetes (EKS) Monitoring
- Multi-Account Support
- Compliance Dashboard
- CIS AWS Benchmark Checks
- AI-based Threat Detection

---

# 📚 Learning Outcomes

This project demonstrates:

- Cloud Computing
- Cloud Security
- AWS SDK (Boto3)
- FastAPI Development
- JWT Authentication
- SQLAlchemy ORM
- REST API Design
- Infrastructure as Code
- Docker Containerization
- AWS Lambda
- Event-Driven Architecture
- Security Monitoring
- CloudTrail Analysis
- Automated Testing

---

# 🎓 Academic Relevance

This project integrates multiple domains of computer science:

- Cloud Computing
- Cyber Security
- Backend Development
- DevOps
- Infrastructure Automation
- Software Engineering

It demonstrates practical implementation of cloud security monitoring and is suitable as a final-year B.Tech project.

---

# 👨‍💻 Author

** Manish Kumar **

**B.Tech – Cloud Technology & Information Security**

---

# 📄 License

This project is developed for educational and academic purposes.

```

### One recommendation

Replace the placeholder:

```text
git clone https://github.com/manishkumar0607/Cloud-Security-Monitoring_-_Threat-Detection-Platform.git
```
