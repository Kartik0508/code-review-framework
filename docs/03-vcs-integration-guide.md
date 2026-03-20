# Version Control Integration Guide

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [GitHub Actions CI Pipeline](#2-github-actions-ci-pipeline)
3. [Webhook Integration](#3-webhook-integration)
4. [How to Integrate With Another Project](#4-how-to-integrate-with-another-project)
5. [Branch Protection Rules](#5-branch-protection-rules)
6. [GitHub Secrets Required](#6-github-secrets-required)

---

## 1. Overview

The framework integrates with GitHub in two ways:

| Integration | How | Works Without Server |
|---|---|---|
| GitHub Actions CI | Workflow file in repo | Yes — runs on GitHub's cloud |
| Webhook | GitHub calls backend API | No — needs public server |

**GitHub Actions** is the primary integration — it runs automatically on every
push and pull request without needing your backend server to be online.

**Webhook** is the secondary integration — it notifies your backend when code
is pushed so results are stored in your central database and Grafana dashboard.

---

## 2. GitHub Actions CI Pipeline

**File:** `.github/workflows/code-review.yml`

### 2.1 Trigger Events
```yaml
on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]
```

The pipeline runs automatically when:
- Code is pushed to `main`, `master`, or `develop`
- A pull request is opened or updated targeting `main` or `master`

### 2.2 Pipeline Jobs

All jobs run in parallel on GitHub's cloud servers:

#### Job 1 — Semgrep SAST
```
Tool:    Semgrep (via semgrep/semgrep Docker container)
Scans:   OWASP Top 10, Python, JavaScript, Java rules
Output:  SARIF file uploaded to GitHub Security tab
Fails:   If any ERROR severity finding detected
```

#### Job 2 — Bandit Python Security
```
Tool:    Bandit
Scans:   All .py files in the repository
Output:  bandit-report.json uploaded as artifact (30 day retention)
Fails:   If any HIGH severity + non-LOW confidence finding detected
```

#### Job 3 — Gitleaks Secret Detection
```
Tool:    Gitleaks (via gitleaks/gitleaks-action@v2)
Scans:   Full git history (fetch-depth: 0)
Output:  Reported in GitHub Actions log
Fails:   If any secret or credential is detected
```

#### Job 4 — OWASP Dependency Check
```
Tool:    OWASP Dependency-Check (via dependency-check/Dependency-Check_Action)
Scans:   All dependency manifests (requirements.txt, package.json, etc.)
Output:  JSON report uploaded as artifact (30 day retention)
Fails:   If any dependency has CVSS score >= 7.0
```

#### Job 5 — CodeQL Analysis
```
Tool:    CodeQL (GitHub's semantic analysis engine)
Scans:   Python and JavaScript (matrix strategy — runs both in parallel)
Output:  Results uploaded to GitHub Security tab
Fails:   If critical security findings detected
Queries: security-and-quality
```

#### Job 6 — Notify Framework (runs after all above complete)
```
Purpose: Sends scan completion notification to FastAPI backend
Method:  HTTP POST to /scans/webhook/github
Needs:   CODE_REVIEW_API_URL and CODE_REVIEW_API_TOKEN secrets
Fails:   Gracefully (uses || true — does not block other jobs)
```

### 2.3 Viewing Results

**GitHub Actions tab:**
- Go to your repo on GitHub
- Click `Actions` tab
- See all pipeline runs with pass/fail status

**GitHub Security tab:**
- Go to your repo on GitHub
- Click `Security` tab → `Code scanning alerts`
- See all Semgrep and CodeQL findings with file locations

**Artifacts:**
- Go to a specific Actions run
- Scroll down to `Artifacts` section
- Download `bandit-report` or `dependency-check-report`

---

## 3. Webhook Integration

### 3.1 How It Works
```
Developer pushes code to GitHub
              ↓
GitHub sends HTTP POST to your backend:
POST https://your-server.com/scans/webhook/github
              ↓
Backend validates HMAC-SHA256 signature
              ↓
Backend identifies project by repo URL
              ↓
Backend triggers scans: semgrep + bandit + gitleaks
              ↓
Results saved in database → visible in Grafana
```

### 3.2 Webhook Endpoint
```
POST /scans/webhook/github
```

**Validation:** HMAC-SHA256 signature verified via `X-Hub-Signature-256` header

**Branches scanned:** Only `main` and `master` (other branches ignored)

**Scanners triggered:** Semgrep, Bandit, Gitleaks

### 3.3 Setting Up Webhook in GitHub

1. Go to your GitHub repo → **Settings** → **Webhooks** → **Add webhook**
2. **Payload URL:** `https://your-server.com/scans/webhook/github`
3. **Content type:** `application/json`
4. **Secret:** Same value as `GITHUB_WEBHOOK_SECRET` in your `.env`
5. **Events:** Select `Just the push event`
6. Click **Add webhook**

### 3.4 Local Testing with ngrok

Since the backend runs on `localhost`, use ngrok for local testing:

```bash
# Install ngrok
# Download from https://ngrok.com/download

# Expose local port 8000
ngrok http 8000

# ngrok gives you a public URL like:
# https://abc123.ngrok.io

# Use this as your webhook URL:
# https://abc123.ngrok.io/scans/webhook/github
```

**Note:** ngrok URL changes every time you restart it. For permanent webhook,
deploy backend to a cloud platform.

---

## 4. How to Integrate With Another Project

### Option A — Copy the GitHub Actions Workflow

Any GitHub project can use this framework's scanning by copying the workflow:

1. Copy `.github/workflows/code-review.yml` to their repo
2. Add required GitHub Secrets (see Section 6)
3. Push — scans run automatically on every push/PR

**Result:** Their code gets scanned by all 5 tools automatically.
Results appear in their GitHub Security tab and Actions artifacts.

### Option B — Reference as Reusable Workflow

They add one line to their workflow:
```yaml
jobs:
  security-scan:
    uses: Kartik0508/code-review-framework/.github/workflows/code-review.yml@main
```

### Option C — Register Project and Use Webhook

For teams who want results in the central Grafana dashboard:

1. Admin registers their project via API:
```bash
POST /projects/
{
  "name": "My Project",
  "repo_url": "https://github.com/their-org/their-repo.git"
}
```

2. They add webhook in their GitHub repo pointing to your backend
3. Every push triggers scans and results appear in your Grafana dashboard

---

## 5. Branch Protection Rules

To enforce security scans before merging, configure branch protection in GitHub:

1. Go to repo → **Settings** → **Branches** → **Add rule**
2. Branch name pattern: `main`
3. Enable: **Require status checks to pass before merging**
4. Add required checks:
   - `Semgrep SAST`
   - `Bandit Python Security`
   - `Gitleaks Secret Detection`
   - `OWASP Dependency Check`
   - `CodeQL Analysis`
5. Enable: **Require branches to be up to date before merging**

**Result:** PRs cannot be merged until all security scans pass.

---

## 6. GitHub Secrets Required

Add these in GitHub repo → **Settings** → **Secrets and variables** → **Actions**:

| Secret Name | Value | Required For |
|---|---|---|
| `SONAR_TOKEN` | SonarQube authentication token | SonarQube job (if added) |
| `SONAR_HOST_URL` | `http://your-sonarqube-server:9000` | SonarQube job (if added) |
| `GITLEAKS_LICENSE` | Gitleaks license key (optional) | Gitleaks job |
| `CODE_REVIEW_API_URL` | Your backend public URL | notify-framework job |
| `CODE_REVIEW_API_TOKEN` | JWT token for backend authentication | notify-framework job |

**Note:** `GITHUB_TOKEN` is automatically provided by GitHub Actions — no setup needed.

---

*Document Version 1.0 — Secure Code Review Framework*
