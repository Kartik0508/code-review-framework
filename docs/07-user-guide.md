# User Training & Documentation

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [For Developers](#3-for-developers)
4. [For Reviewers](#4-for-reviewers)
5. [For Admins](#5-for-admins)
6. [Understanding Scan Results](#6-understanding-scan-results)
7. [Issue Lifecycle](#7-issue-lifecycle)
8. [Secure Coding Best Practices](#8-secure-coding-best-practices)
9. [Frequently Asked Questions](#9-frequently-asked-questions)

---

## 1. Introduction

The Secure Code Review Framework automatically scans your code for security
vulnerabilities every time you push to GitHub. It uses 5 industry-standard
scanners to detect:

- Security vulnerabilities in your code (SQL injection, XSS, etc.)
- Exposed secrets and API keys committed to the repository
- Vulnerable third-party dependencies with known CVEs
- Code quality issues that lead to security problems

**The framework runs automatically — you do not need to do anything extra
when pushing code. Scans trigger on their own.**

---

## 2. Getting Started

### 2.1 Starting All Services

Before using the framework, ensure all services are running:

```bash
# 1. Start SonarQube
sudo systemctl start sonarqube

# 2. Start Grafana
sudo systemctl start grafana-server

# 3. Start FastAPI Backend
cd /home/dell/code-review-framework
source .venv/bin/activate
PYTHONPATH=/home/dell/code-review-framework \
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2.2 Accessing the Tools

| Tool | URL | Purpose |
|---|---|---|
| API & Swagger UI | http://localhost:8000/docs | Test API, trigger scans |
| Grafana Dashboard | http://localhost:3000 | Visual security dashboard |
| SonarQube | http://localhost:9000 | Deep code analysis |

### 2.3 Default Credentials

| Tool | Username | Password |
|---|---|---|
| Framework API | admin | admin123 |
| Grafana | admin | admin (change on first login) |
| SonarQube | admin | (set during setup) |

---

## 3. For Developers

As a developer, your role is to write code and address security issues found in your code.

### 3.1 Register Your Account

1. Open http://localhost:8000/docs
2. Find `POST /auth/register`
3. Click **Try it out** and fill in:
```json
{
  "username": "your_username",
  "email": "you@company.com",
  "password": "SecurePassword123!"
}
```
4. Click **Execute**
5. You will receive a response confirming your account was created

**Note:** New accounts have `developer` role. Ask admin to upgrade if needed.

### 3.2 Login and Get Your Token

1. Find `POST /auth/login` in Swagger
2. Click **Try it out**
3. Enter your `username` and `password`
4. Copy the `access_token` from the response
5. Click the **Authorize** button at the top of Swagger
6. Enter: `Bearer paste-your-token-here`
7. Click **Authorize**

You are now authenticated for all subsequent API calls.

### 3.3 View Scan Results

After pushing code, wait 1-2 minutes for scans to complete.

**View all scans:**
```
GET /scans/
```

**View scans for a specific project:**
```
GET /scans/?project_id={project-uuid}
```

**View issues from a scan:**
```
GET /scans/{scan_id}/issues
```

**Filter by severity:**
```
GET /scans/{scan_id}/issues?severity=HIGH
```

### 3.4 Comment on an Issue

If you believe a finding is a false positive or have context to add:

```
POST /scans/{scan_id}/issues/{issue_id}/comments

{
  "body": "This is using SQLAlchemy ORM parameterization,
           not raw string concatenation. Likely false positive."
}
```

### 3.5 View Comments on an Issue

```
GET /scans/{scan_id}/issues/{issue_id}/comments
```

### 3.6 Understanding Your GitHub Actions Results

After pushing to GitHub:
1. Go to your repo on GitHub
2. Click the **Actions** tab
3. Click the latest workflow run
4. Green checkmark = all scans passed
5. Red X = a scanner found critical issues

For detailed findings:
- Go to **Security** tab → **Code scanning alerts**
- See exact file and line number of each issue

---

## 4. For Reviewers

As a reviewer, you assess issues found by scanners and make decisions on their validity and priority.

### 4.1 Review Open Issues

Get all open issues across all scans:
```
GET /scans/?scan_status=completed
```

Then for each scan:
```
GET /scans/{scan_id}/issues?issue_status=open
```

### 4.2 Mark Issue as Resolved

When a developer has fixed an issue:
```
PUT /scans/{scan_id}/issues/{issue_id}

{
  "status": "resolved"
}
```

### 4.3 Mark Issue as False Positive

When an issue is not a real vulnerability:
```
PUT /scans/{scan_id}/issues/{issue_id}

{
  "status": "false_positive"
}
```

**Best practice:** Before marking as false positive, add a comment explaining why:
```
POST /scans/{scan_id}/issues/{issue_id}/comments

{
  "body": "Confirmed false positive. The code uses
           parameterized queries via SQLAlchemy.
           Semgrep pattern match is overly broad."
}
```

### 4.4 Trigger a Manual Scan

If you want to scan a specific branch or after a fix:
```
POST /projects/{project_id}/scan

{
  "scanner": "semgrep",
  "branch": "main",
  "commit_sha": "abc123"
}
```

Valid scanners: `semgrep`, `bandit`, `gitleaks`, `dependency-check`, `sonarqube`

### 4.5 Export Report for Management

Download all open issues as CSV:
```
GET /reports/export/csv
```

View OWASP compliance status:
```
GET /reports/compliance
```

---

## 5. For Admins

As an admin you have full control over the platform.

### 5.1 Create a New Project

```
POST /projects/

{
  "name": "My Application",
  "description": "Main product backend",
  "repo_url": "https://github.com/company/my-app.git",
  "sonarqube_project_key": "my-app"
}
```

### 5.2 Manage Users

**View all users:**
```
GET /users/
```

**Change a user's role:**
```
PUT /users/{user_id}/role

{
  "role": "reviewer"
}
```

**Deactivate a user:**
```
DELETE /users/{user_id}
```

### 5.3 Monitor All Projects

View summary across all projects:
```
GET /reports/summary
```

View per-project summary:
```
GET /reports/summary?project_id={uuid}
```

### 5.4 Delete a Comment

If a comment is inappropriate:
```
DELETE /scans/{scan_id}/issues/{issue_id}/comments/{comment_id}
```

Only admins can delete other users' comments.

---

## 6. Understanding Scan Results

### 6.1 Severity Levels

| Severity | Meaning | What to Do |
|---|---|---|
| CRITICAL | Severe, immediately exploitable | Fix before merging. Do not ignore. |
| HIGH | Significant risk, likely exploitable | Fix within 24 hours |
| MEDIUM | Moderate risk, specific conditions needed | Fix within current sprint |
| LOW | Minor risk, limited impact | Fix when convenient |
| INFO | Best practice recommendation | Review and decide |

### 6.2 Reading an Issue

Each issue contains:

```
rule_id:        bandit-B602
severity:       HIGH
title:          subprocess call with shell=True
description:    subprocess call with shell=True identified, security issue.
file_path:      backend/scanners/semgrep_scanner.py
line_start:     45
cwe_id:         CWE-78
owasp_category: A03:2021 - Injection
remediation:    Avoid shell=True in subprocess calls. Pass arguments
                as a list instead: subprocess.run(['cmd', 'arg1'])
status:         open
```

### 6.3 What Each Field Means

| Field | Description |
|---|---|
| rule_id | The specific rule that triggered (e.g., B602 = Bandit test 602) |
| severity | How serious the issue is |
| title | Short description |
| description | Detailed explanation of the vulnerability |
| file_path | Exact file where the issue was found |
| line_start | Line number in the file |
| cwe_id | CWE number — look up at cwe.mitre.org |
| owasp_category | OWASP Top 10 category |
| remediation | How to fix it |
| status | open / resolved / false_positive |

### 6.4 Understanding CWE IDs

CWE (Common Weakness Enumeration) is a universal classification system for
software weaknesses. Common ones you will see:

| CWE | Meaning | Common Fix |
|---|---|---|
| CWE-78 | OS Command Injection | Avoid shell=True, use argument lists |
| CWE-89 | SQL Injection | Use parameterized queries / ORM |
| CWE-79 | Cross-site Scripting | Escape output, use template auto-escaping |
| CWE-798 | Hardcoded Credentials | Move to environment variables |
| CWE-327 | Weak Cryptography | Use SHA-256 or stronger, not MD5/SHA1 |
| CWE-502 | Insecure Deserialization | Avoid pickle, use JSON |
| CWE-1035 | Vulnerable Dependency | Upgrade the affected package |

---

## 7. Issue Lifecycle

The typical lifecycle of a security issue in the framework:

```
1. DETECTED
   Scanner finds issue during scan
   Status: open
   Action: Issue appears in dashboard and API
              ↓
2. REVIEWED
   Developer sees the issue
   Developer adds comment explaining context
   Status: open
   Action: POST /issues/{id}/comments
              ↓
3. ASSESSED
   Reviewer reads comment and investigates
   Two outcomes:

   A. REAL ISSUE              B. FALSE POSITIVE
      Reviewer adds comment      Reviewer adds comment
      "Confirmed. Fix required"  "False positive. ORM used."
      Status: open               Status: false_positive
              ↓
4. FIXED (if real issue)
   Developer fixes the code
   Developer adds comment: "Fixed in commit abc"
   Triggers new scan
              ↓
5. VERIFIED
   Reviewer confirms fix in new scan
   Marks status: resolved
   Issue closed with full audit trail
```

---

## 8. Secure Coding Best Practices

### 8.1 Never Hardcode Secrets
**Wrong:**
```python
API_KEY = "sk-abc123xyz"
DATABASE_PASSWORD = "mysecretpassword"
```

**Right:**
```python
import os
API_KEY = os.environ.get("API_KEY")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
```

### 8.2 Use Parameterized Queries
**Wrong (SQL Injection risk):**
```python
query = "SELECT * FROM users WHERE id = " + user_id
db.execute(query)
```

**Right:**
```python
db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Or use ORM:
db.query(User).filter(User.id == user_id).first()
```

### 8.3 Avoid Shell Injection
**Wrong:**
```python
subprocess.run(f"scan {user_input}", shell=True)
```

**Right:**
```python
subprocess.run(["scan", user_input])
```

### 8.4 Use Strong Cryptography
**Wrong:**
```python
import hashlib
hashlib.md5(password.encode()).hexdigest()
```

**Right:**
```python
import bcrypt
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 8.5 Validate All Input
**Wrong:**
```python
file_path = request.args.get("file")
with open(file_path) as f:  # Path traversal risk
    return f.read()
```

**Right:**
```python
import os
file_path = os.path.basename(request.args.get("file"))
safe_path = os.path.join("/safe/directory", file_path)
if not safe_path.startswith("/safe/directory"):
    raise ValueError("Invalid path")
with open(safe_path) as f:
    return f.read()
```

---

## 9. Frequently Asked Questions

**Q: How long does a scan take?**
A: Gitleaks ~5 seconds, Bandit ~2 seconds, Semgrep ~19 seconds, Dependency-Check ~6 seconds (after first run).

**Q: Why did GitHub Actions fail?**
A: A scanner found a CRITICAL or HIGH severity issue. Go to Actions tab → click the failed run → see which job failed and why.

**Q: What is a false positive?**
A: When a scanner flags something as a vulnerability but it is actually safe code. Mark it as `false_positive` via the API with a comment explaining why.

**Q: Why does Dependency-Check take so long the first time?**
A: It downloads 338,000+ CVE records from the NVD database. This is a one-time download — all subsequent runs use the cached database and take ~6 seconds.

**Q: Can I scan any GitHub repository?**
A: Yes — create a project with the repo URL, then trigger a scan. The backend will clone the repo and run all scanners on it.

**Q: How do I know if my PR is safe to merge?**
A: Check GitHub Actions — all jobs must show green checkmarks. If any are red, review the findings and fix critical/high issues before merging.

**Q: My token expired. What do I do?**
A: Call `POST /auth/login` again with your credentials to get a new token. Tokens expire after 8 hours.

**Q: Who can see all projects and scans?**
A: Reviewers and admins can see all projects. Developers can see all scans and issues but cannot modify project settings.

---

*Document Version 1.0 — Secure Code Review Framework*
*For support, refer to the project repository at github.com/Kartik0508/code-review-framework*
