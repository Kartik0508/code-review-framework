# Secure Code Review Framework — Progress Report

**Date:** 20 March 2026
**Author:** Kartik
**Project:** Implementing a Secure Framework for a Code Review Tool
**Assigned On:** 1 March 2026
**Deadline:** 21 March 2026

---

## 1. Project Overview

The goal of this project is to build a unified, automated platform that detects
security vulnerabilities across multiple programming languages, integrates with
version control systems, enforces OWASP/SANS/CERT security standards, and
provides visual dashboards and compliance reports — using only free and
open-source tools.

---

## 2. What Has Been Completed

### 2.1 Infrastructure Setup (Task 1 — Done)

- **SonarQube 10** installed natively on Ubuntu (not Docker)
  - Runs as a systemd service under the `sonar` user
  - Uses Java 21 via `SONAR_JAVA_PATH` in systemd config
  - Accessible at `http://localhost:9000`
  - All quality ratings: **A (Security, Reliability, Maintainability)**
  - Connected to PostgreSQL `sonar` database

- **PostgreSQL 15** running natively
  - Two databases: `sonar` (SonarQube) and `code_review` (FastAPI backend + Grafana)
  - User: `postgres`

- **Grafana 12** installed natively
  - Accessible at `http://localhost:3000`
  - Connected to `code_review` PostgreSQL database
  - Live dashboard imported and showing real scan data

- **FastAPI Backend** running on `http://localhost:8000`
  - Auto-creates DB tables on startup
  - Full Swagger UI at `http://localhost:8000/docs`

---

### 2.2 Static Analysis & Scanning Integration (Task 2 — Done)

All 5 scanners are installed, integrated into the backend, and tested end-to-end:

| Scanner | Type | Language Support | Status |
|---|---|---|---|
| Semgrep | SAST | Python, JS, Java, Go, and more | Working — custom rules applied |
| Bandit | SAST | Python only | Working — all severity levels reported |
| Gitleaks | Secret Detection | All (Git history) | Working |
| OWASP Dependency-Check | SCA | Python, JS, Java, .NET | Working — NVD DB cached |
| SonarQube | SAST + Quality | 25+ languages | Working — All A ratings |

- OWASP Top 10, CWE IDs, and OWASP categories mapped to every issue
- Remediation guidance included with every finding
- All scan results stored in PostgreSQL `issues` table
- **32 custom Semgrep rules** across Python, JavaScript, and Java (all validated)

---

### 2.3 Remediation Guidance (Task 3 — Done)

- Every scanner provides remediation text with each issue
- Each issue stored with: `rule_id`, `severity`, `cwe_id`, `owasp_category`, `remediation`
- Gitleaks includes step-by-step secret rotation and git history cleaning guidance
- Semgrep and Bandit map findings to secure code patterns

---

### 2.4 Version Control Integration (Task 4 — Done)

**GitHub Actions CI — Done:**

The `.github/workflows/code-review.yml` pipeline runs automatically on every
push and pull request to `main`, `master`, and `develop` branches.

| Job | Tool | What It Does |
|---|---|---|
| `semgrep` | Semgrep | OWASP Top 10 + Python/JS/Java scan |
| `bandit` | Bandit | Python security scan |
| `gitleaks` | Gitleaks | Full git history secret scan |
| `dependency-check` | OWASP DC | CVE dependency check |
| `codeql` | CodeQL | Deep semantic analysis (Python + JS) |
| `notify-framework` | curl | Sends results to FastAPI backend |

**Webhook — Built and Demonstrated:**
- `POST /scans/webhook/github` endpoint fully functional
- Validates HMAC-SHA256 signatures from GitHub
- Triggers all 5 scanners automatically on every push
- Demonstrated end-to-end with `test-scan-project` external repo using ngrok
- Every push → 5 scanners trigger automatically (`triggered_by: null` confirmed)

---

### 2.5 Authentication & RBAC (Task 5 — Done)

- **JWT authentication** implemented (`/auth/login`, `/auth/register`)
- **3 role tiers** enforced via `require_role()` dependency:

| Role | Permissions |
|---|---|
| `developer` | View scan results, view issues, add comments |
| `reviewer` | Above + mark issues resolved/false positive, trigger scans, export reports |
| `admin` | All permissions + manage users, manage projects, delete comments |

- Passwords hashed with bcrypt
- Token expiry: 8 hours
- Admin user created and role set via database

---

### 2.6 Reporting & Visualization (Task 6 — Done)

**Grafana Dashboard (live at http://localhost:3000):**
- 7 panels: Issues by Severity, Issues by Scanner, New Issues Over Time,
  OWASP Top 10 Distribution, Recent Scan Results, Top Issues by File, CWE Breakdown

**Reports API (available at /reports/):**

| Endpoint | Description |
|---|---|
| `GET /reports/summary` | Total scans, open issues by severity |
| `GET /reports/trends` | 12-week issue trend data |
| `GET /reports/compliance` | Full OWASP Top 10 compliance breakdown |
| `GET /reports/export/csv` | Download all open issues as CSV file |

---

### 2.7 Issue Commenting (Task 7 — Done)

- `IssueComment` database model with full relationship to Issue and User
- Three endpoints implemented and tested:
  - `POST /scans/{scan_id}/issues/{issue_id}/comments` — add comment
  - `GET /scans/{scan_id}/issues/{issue_id}/comments` — view all comments
  - `DELETE /scans/{scan_id}/issues/{issue_id}/comments/{comment_id}` — delete (admin or author only)
- Comments include `author_username` in response
- Supports full issue lifecycle discussion between developers and reviewers

---

### 2.8 Custom Semgrep Rules (Task 7 — Done)

- 32 custom rules across 3 files:
  - `semgrep-rules/owasp-python.yml` — Python OWASP rules
  - `semgrep-rules/owasp-javascript.yml` — JavaScript OWASP rules
  - `semgrep-rules/owasp-java.yml` — Java OWASP rules
- All rules validated (`semgrep --validate` — 0 errors)
- Rules applied automatically to every scan
- Coverage: A01 Path Traversal, A02 Crypto Failures, A03 Injection, A05 Misconfiguration,
  A07 Auth Failures, A08 Prototype Pollution, A09 Logging, A10 SSRF

---

### 2.9 All 7 Deliverable Documents (Done)

| Document | File |
|---|---|
| Architecture & Configuration | `docs/01-architecture.md` |
| Static Analysis Rule Set | `docs/02-static-analysis-rules.md` |
| Version Control Integration Guide | `docs/03-vcs-integration-guide.md` |
| Authentication & RBAC Documentation | `docs/04-auth-rbac.md` |
| Reporting & Visualization Setup | `docs/05-reporting-visualization.md` |
| Performance Optimization Report | `docs/06-performance-report.md` |
| User Training & Documentation | `docs/07-user-guide.md` |

---

### 2.10 Security Hardening (Done Today)

- Removed `.env` file completely from git history using `git filter-branch`
- Force pushed cleaned history to GitHub
- Verified no real credentials were exposed (only placeholder values were committed)
- All 4 Gitleaks findings in the framework repo are false positives (example code in docs)

---

## 3. End-to-End Webhook Test (Proven Today)

Tested with a real external repo (`test-scan-project`):

```
Developer pushes code to GitHub
        ↓
GitHub sends webhook to ngrok → localhost:8000
        ↓
Backend receives push event, identifies project
        ↓
All 5 scanners triggered automatically (triggered_by: null)
        ↓
Results stored in PostgreSQL
        ↓
Visible in Grafana dashboard + API
```

**Results from test-scan-project scan:**

| Scanner | Status | Findings |
|---|---|---|
| Semgrep | completed | 2 high issues |
| Bandit | completed | 0 (no Python security issues above threshold) |
| Gitleaks | completed | 0 secrets |
| Dependency-Check | completed | 0 vulnerabilities |
| SonarQube | completed | 0 issues |

---

## 4. What is Still Optional (Not Required for Submission)

| Item | Notes |
|---|---|
| PDF report export | CSV export works — PDF is nice to have |
| Webhook live 24/7 | Needs public server — demoed with ngrok |
| Custom rule API | Rules work via folder — API CRUD not built |
| Bitbucket support | Only GitHub webhooks supported |

---

## 5. Summary Table

| Task | Requirement | Status |
|---|---|---|
| Task 1 | Framework selection + modular architecture | ✅ Done |
| Task 1 | Native installation of all tools | ✅ Done |
| Task 2 | Static analysis + vulnerability scanning (5 tools) | ✅ Done |
| Task 2 | OWASP Top 10 + CWE + SANS mapping | ✅ Done |
| Task 2 | 32 custom Semgrep rules (Python, JS, Java) | ✅ Done |
| Task 3 | Remediation guidance per issue | ✅ Done |
| Task 4 | GitHub Actions CI pipeline (5 jobs) | ✅ Done |
| Task 4 | Webhook — all 5 scanners, proven with external repo | ✅ Done |
| Task 5 | JWT Authentication | ✅ Done |
| Task 5 | RBAC (admin/reviewer/developer) | ✅ Done |
| Task 6 | Grafana dashboard (7 panels, live data) | ✅ Done |
| Task 6 | CSV export + compliance + trend reports | ✅ Done |
| Task 7 | Issue status tracking (open/resolved/false positive) | ✅ Done |
| Task 7 | Issue commenting for team collaboration | ✅ Done |
| Task 8 | All 7 deliverable documents | ✅ Done |
| — | Git history cleaned — no secrets exposed | ✅ Done |

---

*This report reflects the state of the project as of 20 March 2026.*
*The framework is fully complete and ready for submission on 21 March 2026.*
