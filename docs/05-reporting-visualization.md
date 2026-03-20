# Reporting & Visualization Setup

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Grafana Dashboard](#2-grafana-dashboard)
3. [Reports API](#3-reports-api)
4. [CSV Export](#4-csv-export)
5. [Compliance Report](#5-compliance-report)
6. [Trend Analysis](#6-trend-analysis)

---

## 1. Overview

The framework provides two layers of reporting:

| Layer | Tool | Access | Purpose |
|---|---|---|---|
| Visual Dashboard | Grafana | http://localhost:3000 | Live visual charts and metrics |
| Reports API | FastAPI | http://localhost:8000/reports/ | Programmatic data access + CSV export |

Both pull live data from the `code_review` PostgreSQL database.

---

## 2. Grafana Dashboard

**URL:** http://localhost:3000
**Dashboard:** Code Review Security Dashboard
**Refresh Rate:** Every 5 minutes automatically
**Time Range:** Last 30 days (adjustable)

### 2.1 Dashboard Panels

#### Row 1 — Summary Stats (5 panels)

| Panel | Type | Query | Threshold |
|---|---|---|---|
| Total Open Issues | Stat | COUNT of open issues | Green < 10, Yellow < 50, Red ≥ 50 |
| Critical Issues | Stat | COUNT of CRITICAL open issues | Green = 0, Orange ≥ 1, Red ≥ 5 |
| High Issues | Stat | COUNT of HIGH open issues | Green < 5, Yellow < 20, Orange ≥ 20 |
| Total Scans Run | Stat | COUNT of completed scans | Blue (informational) |
| Projects Monitored | Stat | COUNT of active projects | Blue (informational) |

#### Row 2 — Distribution Charts (3 panels)

**Issues by Severity (Bar Chart)**
Shows count of open issues grouped by severity level.
Color coded: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green

**Issues by Scanner (Pie Chart)**
Shows which scanner found the most issues.
Helps identify which tool is most active on your codebase.

**New Issues Over Time — 30 Days (Time Series)**
Shows daily count of new issues per severity over the last 30 days.
Useful for tracking whether security debt is increasing or decreasing.

#### Row 3 — Compliance & History (2 panels)

**OWASP Top 10 Distribution (Horizontal Bar Chart)**
Shows issue count per OWASP category.
Identifies which OWASP categories have the most violations.

**Recent Scan Results (Table)**
Shows last 20 scans with:
- Project name
- Scanner used
- Status (completed/failed/running)
- Branch
- Start and finish time
- Issues found count

#### Row 4 — Deep Dive (2 panels)

**Top Issues by File (Table)**
Shows the 15 files with the most open issues.
Helps prioritize which files need the most attention.

**CWE Breakdown (Table)**
Shows issue count grouped by CWE ID.
Helps understand which weakness categories are most common.

### 2.2 Grafana Setup

**Datasource Configuration:**
File: `grafana/provisioning/datasources/datasource.yml`
- Type: PostgreSQL
- Database: `code_review`
- Host: `localhost:5432`

**Import Dashboard:**
1. Open Grafana at http://localhost:3000
2. Go to **Dashboards** → **Import**
3. Upload `grafana/dashboards/code_review_dashboard.json`
4. Select the PostgreSQL datasource
5. Click **Import**

**Auto-provisioning:**
The datasource is auto-provisioned via `grafana/provisioning/` on Grafana startup.

### 2.3 Current Live Data (as of 20 March 2026)

```
Total Open Issues:    97
Critical Issues:       1  (secret detected — API key in test file)
High Issues:          32
Total Scans Run:       5
Projects Monitored:    1
```

---

## 3. Reports API

**Base URL:** `http://localhost:8000/reports/`
**Authentication:** Required (Bearer token)

### 3.1 Summary Report

**Endpoint:** `GET /reports/summary`

**Optional filter:** `?project_id={uuid}`

**Response:**
```json
{
  "total_scans": 5,
  "open_issues": 97,
  "critical_count": 1,
  "high_count": 32,
  "medium_count": 60,
  "low_count": 4,
  "scanners_used": ["semgrep", "bandit", "gitleaks", "dependency-check"]
}
```

**Use case:** Executive summary — quick overview of security posture.

---

### 3.2 Trend Report

**Endpoint:** `GET /reports/trends`

**Optional filter:** `?project_id={uuid}`

**Response:** 12 weeks of data, one entry per week:
```json
[
  {
    "week": "2026-W01",
    "critical": 0,
    "high": 5,
    "medium": 12,
    "low": 3
  },
  ...
]
```

**Use case:** Track whether security debt is improving or worsening over time.

---

### 3.3 Compliance Report

**Endpoint:** `GET /reports/compliance`

**Optional filter:** `?project_id={uuid}`

**Response:** One entry per OWASP Top 10 category:
```json
[
  {
    "category": "A01:2021 - Broken Access Control",
    "count": 5,
    "risk_level": "HIGH"
  },
  {
    "category": "A03:2021 - Injection",
    "count": 12,
    "risk_level": "CRITICAL"
  },
  ...
]
```

**Use case:** Compliance audits — show which OWASP categories have open violations.

---

## 4. CSV Export

**Endpoint:** `GET /reports/export/csv`

**Optional filter:** `?project_id={uuid}`

**Response:** Downloadable CSV file with all open issues.

**Filename format:** `issues_YYYYMMDD_HHMMSS.csv`

**CSV Columns:**

| Column | Description |
|---|---|
| ID | Unique issue UUID |
| Scan ID | Which scan found this issue |
| Rule | Scanner rule ID that triggered |
| Severity | CRITICAL / HIGH / MEDIUM / LOW |
| Title | Short description of the vulnerability |
| File | File path where issue was found |
| Line Start | Line number of the issue |
| CWE | CWE ID (e.g., CWE-798) |
| OWASP Category | OWASP Top 10 category |
| Status | open / resolved / false_positive |
| Created At | When the issue was first detected |

**How to download:**

**Via Swagger:**
1. Open http://localhost:8000/docs
2. Find `GET /reports/export/csv`
3. Click **Try it out** → **Execute**
4. Click **Download file**

**Via curl:**
```bash
curl -H "Authorization: Bearer your-token" \
     http://localhost:8000/reports/export/csv \
     -o issues-report.csv
```

**Use case:** Compliance reports for auditors, management reporting, offline analysis.

---

## 5. Compliance Report

The compliance report maps every open issue to its OWASP Top 10 category and
shows how many violations exist per category with their risk level.

**Risk levels per OWASP category:**

| OWASP Category | Risk Level |
|---|---|
| A01 - Broken Access Control | HIGH |
| A02 - Cryptographic Failures | HIGH |
| A03 - Injection | CRITICAL |
| A04 - Insecure Design | MEDIUM |
| A05 - Security Misconfiguration | HIGH |
| A06 - Vulnerable Components | HIGH |
| A07 - Auth & Session Failures | CRITICAL |
| A08 - Software Integrity Failures | HIGH |
| A09 - Logging & Monitoring Failures | MEDIUM |
| A10 - Server-Side Request Forgery | HIGH |

**How to use for compliance audits:**
1. Call `GET /reports/compliance`
2. Any category with `count > 0` has open violations
3. Export issues for that category via CSV with filters
4. Share with auditors as evidence of findings and remediation status

---

## 6. Trend Analysis

The trends endpoint provides 12 weeks of historical data showing how many new
issues were created each week per severity level.

**Interpreting trends:**

```
Week       Critical  High  Medium  Low
2026-W01      0       3      8      2   ← Baseline
2026-W02      0       5     12      1   ← More issues found (new scan)
2026-W03      0       2      4      0   ← Improvements made
2026-W04      1       8     15      3   ← New code introduced vulnerabilities
```

**What good looks like:**
- Critical count trending toward 0
- High count decreasing week over week
- New issues introduced < issues resolved

**What bad looks like:**
- Critical count increasing
- Same issues reappearing after being marked resolved
- Large spikes after new feature deployments

---

*Document Version 1.0 — Secure Code Review Framework*
