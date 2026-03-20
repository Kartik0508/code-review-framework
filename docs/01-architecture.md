# Architecture & Configuration Document

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Component Breakdown](#3-component-breakdown)
4. [Technology Stack & Rationale](#4-technology-stack--rationale)
5. [Data Flow](#5-data-flow)
6. [Database Design](#6-database-design)
7. [Installation & Setup](#7-installation--setup)
8. [Configuration Files](#8-configuration-files)
9. [Service Ports & URLs](#9-service-ports--urls)

---

## 1. System Overview

The Secure Code Review Framework is a unified, automated security scanning
platform designed for software development teams. It integrates multiple
open-source static analysis tools into a single platform with a central API,
database, and visualization dashboard.

**Core Purpose:**
- Automatically detect security vulnerabilities in source code
- Map findings to OWASP Top 10, SANS CWE, and CERT standards
- Provide actionable remediation guidance for every finding
- Enable team collaboration on issue resolution
- Track security posture over time via dashboards and reports

**Design Principles:**
- 100% free and open-source tools
- Native installation (no Docker dependency)
- Modular architecture — each scanner is independent
- API-first design — all features accessible via REST API
- Non-blocking — scans run in background tasks

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVELOPER WORKSTATION                         │
│                                                                  │
│   Developer writes code → git push → GitHub                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    GITHUB (Version Control)                      │
│                                                                  │
│   Push/PR Event → GitHub Actions CI triggers automatically       │
│   Push Event   → Webhook fires → notifies backend               │
└──────────┬───────────────────────────────────────────┬──────────┘
           │ GitHub Actions                            │ Webhook
           ▼                                           ▼
┌──────────────────────┐              ┌────────────────────────────┐
│  GITHUB ACTIONS CI   │              │   FASTAPI BACKEND          │
│  (GitHub's Servers)  │              │   localhost:8000           │
│                      │              │                            │
│  - Semgrep           │              │  - REST API (Swagger UI)   │
│  - Bandit            │              │  - JWT Authentication      │
│  - Gitleaks          │              │  - RBAC (3 roles)          │
│  - Dependency-Check  │              │  - Background scan tasks   │
│  - CodeQL            │              │  - Scanner orchestration   │
│                      │              │  - Issue management        │
│  Results → GitHub    │              │  - Comment management      │
│  Security Tab        │              │  - Report generation       │
└──────────────────────┘              └──────────────┬─────────────┘
                                                     │
                               ┌─────────────────────┼──────────────────┐
                               │                     │                  │
                               ▼                     ▼                  ▼
                  ┌────────────────────┐  ┌─────────────────┐  ┌───────────────┐
                  │   SCANNERS         │  │   POSTGRESQL    │  │  SONARQUBE    │
                  │   (Local)          │  │   localhost:5432│  │  localhost:9000│
                  │                   │  │                 │  │               │
                  │  - Semgrep        │  │  DB: code_review│  │  DB: sonar    │
                  │  - Bandit         │  │  - users        │  │               │
                  │  - Gitleaks       │  │  - projects     │  │  - Static     │
                  │  - OWASP DC       │  │  - scan_results │  │    analysis   │
                  │  - SonarQube CLI  │  │  - issues       │  │  - Quality    │
                  │                   │  │  - issue_comments│  │    gates      │
                  └────────────────────┘  │  - audit_logs   │  │  - Security  │
                                          └────────┬────────┘  │    ratings   │
                                                   │           └───────────────┘
                                                   ▼
                                      ┌────────────────────────┐
                                      │   GRAFANA              │
                                      │   localhost:3000        │
                                      │                        │
                                      │  - Security dashboard  │
                                      │  - Issue trends        │
                                      │  - OWASP compliance    │
                                      │  - Scan history        │
                                      └────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 FastAPI Backend
**Location:** `backend/`
**Port:** 8000
**Purpose:** Central API that orchestrates all scanning, stores results, manages users, and serves reports.

**Key modules:**
| Module | File | Purpose |
|---|---|---|
| Main app | `backend/main.py` | FastAPI app initialization, router registration |
| Database | `backend/db/database.py` | SQLAlchemy engine and session management |
| Models | `backend/db/models.py` | 6 database models |
| Schemas | `backend/models/schemas.py` | Pydantic request/response validation |
| Config | `backend/core/config.py` | Environment variable loading |
| Security | `backend/core/security.py` | JWT token generation and validation |
| Auth API | `backend/auth/router.py` | Login and registration endpoints |
| Users API | `backend/api/users.py` | User management endpoints |
| Projects API | `backend/api/projects.py` | Project CRUD + scan trigger |
| Scans API | `backend/api/scans.py` | Scan results, issues, comments, webhook |
| Reports API | `backend/api/reports.py` | Summary, trends, compliance, CSV export |
| Scanner Service | `backend/scanners/scanner_service.py` | Scan orchestration and DB persistence |

---

### 3.2 Security Scanners
**Location:** `backend/scanners/`
**Purpose:** Each scanner is an independent module that inherits from `BaseScanner`.

| Scanner | File | What It Detects |
|---|---|---|
| Semgrep | `semgrep_scanner.py` | OWASP Top 10, code patterns, security rules |
| Bandit | `bandit_scanner.py` | Python-specific security vulnerabilities |
| Gitleaks | `gitleaks_scanner.py` | Secrets, API keys, credentials in git history |
| OWASP Dependency-Check | `dependency_check.py` | Known CVEs in project dependencies |
| SonarQube | `sonarqube.py` | Deep static analysis, quality gates |

**Scanner Architecture:**
```
BaseScanner (abstract)
    ├── scan(repo_path, project_id, scan_id) → ScanOutput
    └── Each scanner implements its own scan() method

ScannerRegistry
    └── Maps scanner name → scanner class
        e.g. "semgrep" → SemgrepScanner

ScannerService
    └── run_scan(scan_id, scanner_name, repo_path)
        ├── Marks scan as "running"
        ├── Clones repo if remote URL
        ├── Calls scanner.scan()
        ├── Saves issues to database
        └── Marks scan as "completed" or "failed"
```

---

### 3.3 PostgreSQL Database
**Port:** 5432
**Databases:**
- `sonar` — used by SonarQube
- `code_review` — used by FastAPI backend and Grafana

---

### 3.4 SonarQube
**Port:** 9000
**Installation:** `/opt/sonarqube`
**Service:** `sudo systemctl start sonarqube`
**Purpose:** Deep static code analysis with quality gates, security ratings (A-F), and built-in issue tracking.

**Current Status:** All ratings A (Security, Reliability, Maintainability)

---

### 3.5 Grafana
**Port:** 3000
**Service:** `sudo systemctl start grafana-server`
**Purpose:** Visual security dashboard pulling live data from the `code_review` PostgreSQL database.

**Dashboard Panels:**
- Total Open Issues (stat)
- Critical Issues (stat)
- High Issues (stat)
- Total Scans Run (stat)
- Projects Monitored (stat)
- Issues by Severity (bar chart)
- Issues by Scanner (pie chart)
- New Issues Over Time — 30 days (time series)
- OWASP Top 10 Distribution (bar chart)
- Recent Scan Results (table)
- Top Issues by File (table)
- CWE Breakdown (table)

---

### 3.6 GitHub Actions CI
**File:** `.github/workflows/code-review.yml`
**Trigger:** Every push to `main`, `master`, `develop` — and every pull request

**Jobs (run in parallel on GitHub's servers):**
| Job | Tool | Purpose |
|---|---|---|
| `semgrep` | Semgrep | OWASP Top 10 + multi-language scan |
| `bandit` | Bandit | Python security scan |
| `gitleaks` | Gitleaks | Secret detection in full git history |
| `dependency-check` | OWASP DC | CVE dependency vulnerability check |
| `codeql` | CodeQL | Deep semantic analysis (Python + JS) |
| `notify-framework` | curl | Notifies FastAPI backend after all scans |

---

## 4. Technology Stack & Rationale

| Tool | Version | License | Why Chosen |
|---|---|---|---|
| FastAPI | Latest | MIT | Fast, async Python API framework with auto Swagger UI |
| SQLAlchemy | 2.0 | MIT | ORM for PostgreSQL with async support |
| PostgreSQL | 15 | PostgreSQL | Reliable, production-grade relational database |
| Pydantic | v2 | MIT | Data validation and serialization |
| PyJWT | Latest | MIT | JWT token generation and validation |
| SonarQube CE | 10 | LGPL v3 | Central analysis hub with quality gates and ratings |
| Semgrep | Latest | LGPL | Fast pattern-based scanning with OWASP rule packs |
| Bandit | Latest | Apache 2 | Python-specific security linter |
| Gitleaks | Latest | MIT | Best-in-class secret and credential detection |
| OWASP DC | Latest | Apache 2 | CVE database scanning for dependencies |
| CodeQL | Latest | MIT/GH | Deep semantic analysis by GitHub |
| Grafana | 12 | AGPL v3 | Flexible dashboards with PostgreSQL datasource |
| GitHub Actions | — | Free | Cloud CI/CD with no server required |

---

## 5. Data Flow

### 5.1 Manual Scan via API
```
User calls POST /projects/{project_id}/scan
                    ↓
Backend creates ScanResult record (status: pending)
                    ↓
Background task starts → ScannerService.run_scan()
                    ↓
Status updated to "running"
                    ↓
If repo_url is remote → git clone to /tmp/scans/{scan_id}/
                    ↓
Scanner.scan(repo_path) called
                    ↓
Scanner runs tool → parses output → returns ScanOutput
                    ↓
Each issue saved to issues table
                    ↓
ScanResult updated → status: "completed", summary, raw_results
                    ↓
Temp clone directory deleted
```

### 5.2 Automated Scan via GitHub Webhook
```
Developer pushes to main/master branch
                    ↓
GitHub sends POST to /scans/webhook/github
                    ↓
Backend validates HMAC-SHA256 signature
                    ↓
Identifies project by repo URL
                    ↓
Creates 3 scan records (semgrep, bandit, gitleaks)
                    ↓
All 3 scans run as background tasks simultaneously
                    ↓
Results saved to database → visible in Grafana
```

### 5.3 GitHub Actions CI Flow
```
Push/PR event on GitHub
        ↓
5 jobs run in parallel on GitHub's cloud servers
        ↓
Each job runs its scanner on the repo code
        ↓
Results uploaded to GitHub Security tab (SARIF)
        ↓
notify-framework job calls backend webhook
        ↓
Backend stores notification in database
```

---

## 6. Database Design

### Tables in `code_review` database

**users**
```
id (UUID PK), username, email, hashed_password,
role (admin/reviewer/developer), is_active, created_at
```

**projects**
```
id (UUID PK), name, description, repo_url,
sonarqube_project_key, created_by (FK→users),
created_at, is_active
```

**scan_results**
```
id (UUID PK), project_id (FK→projects), scanner,
status (pending/running/completed/failed),
triggered_by (FK→users), commit_sha, branch,
started_at, finished_at, summary (JSONB), raw_results (JSONB)
```

**issues**
```
id (UUID PK), scan_id (FK→scan_results), rule_id,
severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), title,
description, file_path, line_start, line_end,
cwe_id (VARCHAR 200), owasp_category, remediation,
status (open/resolved/false_positive), created_at
```

**issue_comments**
```
id (UUID PK), issue_id (FK→issues), user_id (FK→users),
body (TEXT), created_at
```

**audit_logs**
```
id (UUID PK), user_id (FK→users), action,
resource_type, resource_id, details (JSONB),
ip_address, created_at
```

---

## 7. Installation & Setup

### 7.1 Prerequisites
```
- Ubuntu 20.04 or later
- Python 3.11+
- PostgreSQL 15
- Java 21 (for SonarQube)
- Git
```

### 7.2 PostgreSQL Setup
```bash
# Create databases
sudo -u postgres psql
CREATE DATABASE sonar;
CREATE DATABASE code_review;
\q
```

### 7.3 SonarQube Setup
```bash
# Install Java 21
sudo apt install openjdk-21-jdk

# Download and extract SonarQube
sudo wget https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-10.x.zip
sudo unzip sonarqube-10.x.zip -d /opt/
sudo mv /opt/sonarqube-10.x /opt/sonarqube

# Create sonar user
sudo useradd -r -s /bin/false sonar
sudo chown -R sonar:sonar /opt/sonarqube

# Start service
sudo systemctl start sonarqube
# Access at http://localhost:9000 (admin/admin on first login)
```

### 7.4 FastAPI Backend Setup
```bash
# Clone the repo
git clone https://github.com/Kartik0508/code-review-framework.git
cd code-review-framework

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Create .env file (see Section 8.1)

# Start the backend
PYTHONPATH=/home/dell/code-review-framework \
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 7.5 Grafana Setup
```bash
# Install Grafana
sudo apt install grafana

# Start service
sudo systemctl start grafana-server
# Access at http://localhost:3000 (admin/admin on first login)

# Import dashboard
# Go to Dashboards → Import → Upload grafana/dashboards/code_review_dashboard.json
```

### 7.6 Install Scanners
```bash
# Semgrep
pip install semgrep

# Bandit
pip install bandit

# Gitleaks (download binary)
# https://github.com/gitleaks/gitleaks/releases

# OWASP Dependency-Check
# https://github.com/jeremylong/DependencyCheck/releases
```

---

## 8. Configuration Files

### 8.1 Environment Variables (`.env`)
```env
# Database
DATABASE_URL=postgresql://postgres:PASSWORD@localhost:5432/code_review

# Security
SECRET_KEY=your-strong-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# SonarQube
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=your-sonarqube-token

# GitHub
GITHUB_WEBHOOK_SECRET=your-webhook-secret
GITHUB_TOKEN=your-github-token

# Grafana
GRAFANA_ADMIN_PASSWORD=your-grafana-password
```

### 8.2 Grafana Datasource (`grafana/provisioning/datasources/datasource.yml`)
```yaml
apiVersion: 1
datasources:
  - name: PostgreSQL
    type: postgres
    url: localhost:5432
    database: code_review
    user: postgres
    secureJsonData:
      password: "your-password"
    jsonData:
      sslmode: disable
      postgresVersion: 1500
    isDefault: true
```

### 8.3 SonarQube Project (`sonar-project.properties`)
```properties
sonar.projectKey=code-review-framework
sonar.projectName=Code Review Framework
sonar.sources=backend
sonar.language=python
sonar.host.url=http://localhost:9000
sonar.token=your-sonarqube-token
```

---

## 9. Service Ports & URLs

| Service | Port | URL | Start Command |
|---|---|---|---|
| FastAPI Backend | 8000 | http://localhost:8000 | `uvicorn backend.main:app` |
| FastAPI Swagger UI | 8000 | http://localhost:8000/docs | (same) |
| SonarQube | 9000 | http://localhost:9000 | `sudo systemctl start sonarqube` |
| Grafana | 3000 | http://localhost:3000 | `sudo systemctl start grafana-server` |
| PostgreSQL | 5432 | localhost:5432 | Running natively |

---

*Document Version 1.0 — Secure Code Review Framework*
*All tools used are free and open-source.*
