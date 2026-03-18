# Secure Code Review Framework — Comprehensive Project Report

**Project Title:** Implementing a Secure Framework for a Code Review Tool
**Domain:** Cyber Security & Ethical Hacking
**Report Date:** March 2026
**Classification:** Internal Research & Development
**Tools:** 100% Free & Open-Source

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Objectives](#2-project-objectives)
3. [Problem Statement](#3-problem-statement)
4. [Scope & Boundaries](#4-scope--boundaries)
5. [Technology Stack](#5-technology-stack)
6. [System Architecture](#6-system-architecture)
7. [Implementation Plan — Phase by Phase](#7-implementation-plan--phase-by-phase)
8. [Security Standards & Rule Mapping](#8-security-standards--rule-mapping)
9. [Authentication & Access Control Design](#9-authentication--access-control-design)
10. [Reporting & Visualization Design](#10-reporting--visualization-design)
11. [CI/CD Integration Design](#11-cicd-integration-design)
12. [Performance Optimization Strategy](#12-performance-optimization-strategy)
13. [Deliverables Checklist](#13-deliverables-checklist)
14. [Risk Assessment](#14-risk-assessment)
15. [Conclusion & Next Steps](#15-conclusion--next-steps)

---

## 1. Executive Summary

This report describes the design, planning, and implementation strategy for a
**Secure Code Review Framework** — a unified, automated platform that detects
security vulnerabilities, enforces coding standards, and provides actionable
remediation guidance across multiple programming languages and projects.

The framework integrates industry-leading open-source static analysis tools
(SonarQube, Semgrep, CodeQL, Bandit, ESLint) with dependency scanning
(OWASP Dependency-Check), secret detection (Gitleaks), and visual dashboards
(Grafana). It connects directly to version control systems (Git, GitHub,
GitLab) to gate pull requests and commits before they reach production.

All tools selected are **free and open-source**, making this framework
accessible to teams of any size without licensing costs.

---

## 2. Project Objectives

| # | Objective | Success Metric |
|---|-----------|---------------|
| 1 | Set up a modular, scalable code review framework | Supports 5+ languages, handles 100k+ LOC |
| 2 | Integrate static analysis & vulnerability scanning | All 7 tools operational and reporting results |
| 3 | Apply OWASP, SANS, CERT security rules | 100+ rules mapped and active |
| 4 | Provide detailed remediation guidance | Every finding includes fix steps + code examples |
| 5 | Enable VCS integration for automated reviews | PRs blocked on critical findings |
| 6 | Implement authentication, RBAC, collaboration | 3 role types, SSO-capable |
| 7 | Deliver visual dashboards and compliance reports | Grafana live + PDF/CSV export |

---

## 3. Problem Statement

### 3.1 The Security Gap in Modern Development

Most development teams lack a systematic, automated approach to catching
security vulnerabilities before code reaches production. The consequences are
severe:

- **Data breaches** from undetected SQL injection, XSS, or authentication flaws
- **Supply chain attacks** via vulnerable third-party dependencies
- **Secret leaks** — API keys, passwords committed to repositories
- **Compliance failures** — GDPR, PCI-DSS, HIPAA violations from insecure code
- **Costly late fixes** — A bug found in production costs 100x more than one
  caught during development

### 3.2 Current Challenges

```
Challenge 1: Fragmented Tooling
  Developers use different tools, no unified view, results are siloed

Challenge 2: No Automated Enforcement
  Security reviews are manual, inconsistent, and often skipped under deadline pressure

Challenge 3: Missing Remediation Context
  Tools report what is wrong but not how to fix it correctly

Challenge 4: No Standards Alignment
  Rules are not mapped to OWASP/SANS/CERT, making compliance tracking impossible

Challenge 5: Lack of Visibility
  No dashboards or trend tracking — security debt accumulates invisibly
```

### 3.3 What This Framework Solves

This framework creates a **single, automated security gate** embedded into the
development lifecycle — catching vulnerabilities at the earliest possible
moment (during coding, not after deployment) and guiding developers toward
secure alternatives.

---

## 4. Scope & Boundaries

### In Scope

- Static code analysis for Python, JavaScript, Java, C/C++, Go, Ruby, PHP
- Dependency vulnerability scanning for npm, pip, Maven, Gradle, Composer
- Secret and credential detection in Git history and working tree
- Pull request / commit gating via CI/CD integration
- Role-based access control with three permission tiers
- Visual dashboards and exportable compliance reports
- Custom rule creation for organization-specific policies
- Knowledge base of secure coding best practices

### Out of Scope

- Dynamic Application Security Testing (DAST) / runtime scanning
- Penetration testing or exploit development
- Mobile application analysis (iOS/Android)
- Binary analysis or reverse engineering
- Commercial tool integration (all tools must be free/open-source)

### Supported Languages

| Language | Analysis Tools |
|----------|---------------|
| Python | Bandit, Semgrep, SonarQube, CodeQL |
| JavaScript / TypeScript | ESLint + Security Plugin, Semgrep, SonarQube, CodeQL |
| Java | SonarQube, CodeQL, Semgrep |
| C / C++ | CodeQL, Semgrep, SonarQube |
| Go | Semgrep, SonarQube |
| Ruby | Semgrep, SonarQube |
| PHP | SonarQube, Semgrep |

---

## 5. Technology Stack

### 5.1 Core Analysis Tools

```
┌────────────────────────────────────────────────────────────────┐
│  TOOL                  │  PURPOSE                │  LICENSE    │
├────────────────────────┼─────────────────────────┼────────────┤
│  SonarQube CE          │  Central analysis hub   │  LGPL v3   │
│  Semgrep               │  Pattern-based scanning │  LGPL v2.1 │
│  CodeQL                │  Semantic analysis      │  MIT / GH  │
│  Bandit                │  Python security linter │  Apache 2  │
│  ESLint + eslint-      │  JS/TS security rules   │  MIT       │
│  plugin-security       │                         │            │
│  OWASP Dependency-     │  CVE dependency scan    │  Apache 2  │
│  Check                 │                         │            │
│  Gitleaks              │  Secret detection       │  MIT       │
└────────────────────────┴─────────────────────────┴────────────┘
```

### 5.2 Infrastructure & Supporting Tools

```
┌────────────────────────────────────────────────────────────────┐
│  TOOL                  │  PURPOSE                │  LICENSE    │
├────────────────────────┼─────────────────────────┼────────────┤
│  PostgreSQL            │  SonarQube database     │  PostgreSQL│
│  Docker + Compose      │  Container orchestration│  Apache 2  │
│  Grafana               │  Visualization          │  AGPL v3   │
│  Nginx                 │  Reverse proxy / TLS    │  BSD       │
│  GitHub Actions /      │  CI/CD automation       │  Free tier │
│  GitLab CI             │                         │            │
│  Jenkins (optional)    │  Self-hosted CI/CD      │  MIT       │
└────────────────────────┴─────────────────────────┴────────────┘
```

### 5.3 Technology Rationale

**Why SonarQube as the hub?**
SonarQube Community Edition provides a web UI, persistent issue tracking,
quality gates, project management, and built-in RBAC. It acts as the central
dashboard that aggregates issues from all other tools via its API.

**Why Semgrep alongside SonarQube?**
Semgrep excels at custom, organization-specific rules written in YAML. Where
SonarQube provides broad coverage, Semgrep allows precise targeting of patterns
specific to your codebase (e.g., internal framework misuse).

**Why CodeQL?**
CodeQL performs deep semantic analysis — it understands data flow, taint
tracking, and control flow across the entire codebase. It catches complex
multi-step vulnerabilities that pattern-based tools miss.

**Why Grafana?**
SonarQube's built-in charts are limited. Grafana connects to SonarQube's API
and PostgreSQL to build custom trend dashboards, executive-level summaries,
and compliance tracking over time.

---

## 6. System Architecture

### 6.1 High-Level Architecture Diagram

```
 ┌──────────────────────────────────────────────────────────────┐
 │                    DEVELOPER WORKSTATION                      │
 │  Code Editor  →  Git Commit  →  Pre-commit Hook (Gitleaks)   │
 └────────────────────────┬─────────────────────────────────────┘
                          │ git push
                          ▼
 ┌──────────────────────────────────────────────────────────────┐
 │              VERSION CONTROL SYSTEM                          │
 │         GitHub / GitLab / Bitbucket / Self-hosted Git        │
 │                                                              │
 │   Pull Request Created ──→ Webhook Triggered                 │
 └────────────────────────┬─────────────────────────────────────┘
                          │ CI/CD trigger
                          ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  CI/CD PIPELINE                              │
 │         (GitHub Actions / GitLab CI / Jenkins)               │
 │                                                              │
 │  Stage 1: Secret Scan     [Gitleaks]                         │
 │  Stage 2: Dependency Scan [OWASP Dependency-Check]           │
 │  Stage 3: SAST            [Bandit | ESLint | Semgrep]        │
 │  Stage 4: Deep Analysis   [CodeQL]                           │
 │  Stage 5: Quality Gate    [SonarQube Scanner]                │
 │                                                              │
 │  ✓ All pass → PR approved to merge                           │
 │  ✗ Any critical fail → PR blocked, developer notified        │
 └────────────────────────┬─────────────────────────────────────┘
                          │ results pushed
                          ▼
 ┌──────────────────────────────────────────────────────────────┐
 │               ANALYSIS & STORAGE LAYER                       │
 │                                                              │
 │  ┌─────────────────────┐    ┌──────────────────────────┐    │
 │  │   SonarQube Server  │    │      PostgreSQL DB        │    │
 │  │   - Issue tracking  │◄──►│   - Persistent storage   │    │
 │  │   - Quality gates   │    │   - Metrics history      │    │
 │  │   - RBAC / Auth     │    │   - Grafana data source  │    │
 │  │   - REST API        │    └──────────────────────────┘    │
 │  └─────────────────────┘                                     │
 └────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────────────────┐
 │              VISUALIZATION & REPORTING LAYER                 │
 │                                                              │
 │  Grafana Dashboards:                                         │
 │  - Vulnerability trends over time                            │
 │  - Severity breakdown (Critical/High/Medium/Low)             │
 │  - Per-project / per-team security scores                    │
 │  - OWASP Top 10 compliance heatmap                           │
 │  - Dependency risk overview                                  │
 │                                                              │
 │  SonarQube Reports:                                          │
 │  - Project-level security ratings                            │
 │  - Issue lists with remediation steps                        │
 │  - Exportable PDF/CSV compliance reports                     │
 └──────────────────────────────────────────────────────────────┘
```

### 6.2 Data Flow

```
Source Code
    │
    ├─[Gitleaks]──────────────── Secrets/Credentials Found?
    │                                    │
    ├─[OWASP Dep-Check]─────────── CVE in Dependencies?
    │                                    │
    ├─[Bandit]──────────────────── Python Vulnerabilities?
    ├─[ESLint Security]─────────── JS Vulnerabilities?
    ├─[Semgrep]─────────────────── Pattern Rule Violations?
    ├─[CodeQL]──────────────────── Semantic Vulnerabilities?
    │                                    │
    └─[SonarQube Scanner]──────── All results → SonarQube Server
                                         │
                              ┌──────────┴──────────┐
                              │   Quality Gate Check │
                              └──────────┬──────────┘
                                         │
                           ┌─────────────┴──────────────┐
                           │                            │
                      PASS (green)               FAIL (red)
                           │                            │
                    PR can merge              PR blocked
                    Grafana updated           Dev notified
                                             Fix required
```

### 6.3 Deployment Architecture

```
Server / VM (minimum specs: 4 CPU, 8GB RAM, 50GB disk)
│
└── Docker Compose Stack
    ├── sonarqube        (port 9000)   — Analysis hub
    ├── sonarqube-db     (port 5432)   — PostgreSQL
    ├── grafana          (port 3000)   — Dashboards
    └── nginx            (port 80/443) — Reverse proxy + TLS termination
```

---

## 7. Implementation Plan — Phase by Phase

### Phase 1: Foundation & Infrastructure Setup (Week 1-2)

**Goal:** Get the core platform running.

```
Tasks:
  1.1  Install Docker & Docker Compose on host server
  1.2  Write docker-compose.yml for SonarQube + PostgreSQL + Grafana + Nginx
  1.3  Configure Nginx with HTTPS (Let's Encrypt or self-signed cert)
  1.4  Initialize SonarQube — admin password, organizations, projects
  1.5  Connect Grafana to PostgreSQL (SonarQube DB) as data source
  1.6  Verify all services are healthy and accessible
  1.7  Set up automated daily backups of PostgreSQL

Deliverable:
  ✓ Running platform accessible at https://your-domain.com
```

**Key Configuration — docker-compose.yml outline:**
```yaml
services:
  sonarqube:
    image: sonarqube:community
    depends_on: [sonarqube-db]
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://sonarqube-db:5432/sonar
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_logs:/opt/sonarqube/logs
    ports: ["9000:9000"]

  sonarqube-db:
    image: postgres:15
    environment:
      POSTGRES_DB: sonar
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: <strong-password>
    volumes:
      - postgresql_data:/var/lib/postgresql/data

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
    ports: ["3000:3000"]

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    ports: ["80:80", "443:443"]
```

---

### Phase 2: Static Analysis Tool Integration (Week 2-3)

**Goal:** Configure all analysis tools and validate they detect real issues.

```
Tasks:
  2.1  Install and configure Bandit for Python projects
  2.2  Install ESLint + eslint-plugin-security for JavaScript/TypeScript
  2.3  Configure Semgrep with OWASP Top 10 rule pack
  2.4  Set up CodeQL analysis workflows
  2.5  Configure OWASP Dependency-Check
  2.6  Set up Gitleaks for secret scanning
  2.7  Install SonarQube Scanner CLI
  2.8  Write wrapper scripts to run all tools and push results to SonarQube
  2.9  Test all tools against intentionally vulnerable code (DVWA, WebGoat)

Deliverable:
  ✓ All tools detecting vulnerabilities in test code
  ✓ Results visible in SonarQube dashboard
```

**Tool-by-Tool Configuration Details:**

```
Bandit (Python):
  - Config file: .bandit.yaml
  - Severity threshold: MEDIUM and above
  - Tests: B101-B612 (all security tests enabled)
  - Skips: B101 (assert_used) in test files only

ESLint Security (JavaScript):
  - Plugins: eslint-plugin-security, eslint-plugin-no-unsanitized
  - Rules: no-eval, detect-non-literal-regexp, detect-object-injection,
           no-unsanitized/method, no-unsanitized/property

Semgrep:
  - Rule packs: p/owasp-top-ten, p/javascript, p/python, p/java
  - Custom rules directory: ./semgrep-rules/
  - Output: SARIF format for SonarQube import

CodeQL:
  - Queries: security-extended, security-and-quality
  - Languages: javascript, python, java, cpp, go
  - Database build: automatic via codeql database create

OWASP Dependency-Check:
  - NVD API key configured
  - Fail build if CVSS score >= 7.0 (High)
  - Reports: HTML + XML + JSON

Gitleaks:
  - Config: .gitleaks.toml
  - Scans: entire git history + staged changes
  - Custom rules for internal API key formats
```

---

### Phase 3: CI/CD & Version Control Integration (Week 3-4)

**Goal:** Automate scanning on every PR and commit.

```
Tasks:
  3.1  Create GitHub Actions workflow for the full scan pipeline
  3.2  Create GitLab CI equivalent pipeline
  3.3  Configure branch protection rules (require scan pass before merge)
  3.4  Set up PR comments with scan summary (pass/fail + top issues)
  3.5  Configure SonarQube Quality Gates (define pass/fail thresholds)
  3.6  Set up webhook from GitHub/GitLab to SonarQube
  3.7  Implement incremental scanning (scan only changed files for speed)
  3.8  Test end-to-end: push vulnerable code, verify PR is blocked

Deliverable:
  ✓ PRs automatically scanned and blocked on critical findings
  ✓ Developers see inline scan results in their PR
```

**Quality Gate Thresholds (recommended defaults):**
```
BLOCK merge if:
  - Any CRITICAL severity vulnerability found
  - Security Rating drops below A
  - More than 0 new vulnerabilities introduced
  - Coverage drops below 80% (optional)
  - Dependency with CVSS >= 9.0 found
  - Any hardcoded secret detected

WARN (allow merge with approval) if:
  - HIGH severity vulnerability found
  - Code smell density > threshold
  - CVSS 7.0-8.9 dependency found
```

---

### Phase 4: Authentication & RBAC (Week 4-5)

**Goal:** Secure the platform itself and control access.

```
Tasks:
  4.1  Configure SonarQube authentication (local accounts minimum)
  4.2  Optionally configure LDAP/SAML/GitHub OAuth SSO
  4.3  Define three role tiers with specific permissions
  4.4  Create role templates and assign to user groups
  4.5  Configure service accounts for CI/CD pipelines
  4.6  Enable audit logging for all access and configuration changes
  4.7  Enforce strong password policy and optional 2FA
  4.8  Document all role permissions in an access control matrix

Deliverable:
  ✓ All users authenticated, no anonymous access
  ✓ Permission matrix documented and enforced
```

**RBAC Permission Matrix:**
```
┌──────────────────────────┬───────────┬───────────┬───────────┐
│ Permission               │ Developer │ Reviewer  │   Admin   │
├──────────────────────────┼───────────┼───────────┼───────────┤
│ View scan results        │     ✓     │     ✓     │     ✓     │
│ View own project only    │     ✓     │     ✗     │     ✗     │
│ View all projects        │     ✗     │     ✓     │     ✓     │
│ Comment on issues        │     ✓     │     ✓     │     ✓     │
│ Mark issue as resolved   │     ✗     │     ✓     │     ✓     │
│ Mark as false positive   │     ✗     │     ✓     │     ✓     │
│ Create custom rules      │     ✗     │     ✗     │     ✓     │
│ Modify quality gates     │     ✗     │     ✗     │     ✓     │
│ Manage users & roles     │     ✗     │     ✗     │     ✓     │
│ Export compliance reports│     ✗     │     ✓     │     ✓     │
│ Configure integrations   │     ✗     │     ✗     │     ✓     │
│ View audit logs          │     ✗     │     ✗     │     ✓     │
└──────────────────────────┴───────────┴───────────┴───────────┘
```

---

### Phase 5: Reporting & Visualization (Week 5-6)

**Goal:** Make security data visible and actionable.

```
Tasks:
  5.1  Design Grafana dashboard for executive summary view
  5.2  Build vulnerability trend dashboard (issues over time)
  5.3  Build OWASP Top 10 compliance heatmap panel
  5.4  Build per-project / per-team security score dashboard
  5.5  Build dependency risk dashboard
  5.6  Configure SonarQube PDF report plugin
  5.7  Create scheduled weekly/monthly email reports
  5.8  Set up alerting (Slack/email) when critical issues are found

Deliverable:
  ✓ Live Grafana dashboards operational
  ✓ Weekly automated reports generated
  ✓ Alert notifications working
```

**Grafana Dashboard Panels:**
```
Dashboard 1: Executive Security Summary
  - Overall security score (A-F rating)
  - Total open vulnerabilities by severity
  - Projects with active critical issues
  - Month-over-month vulnerability trend

Dashboard 2: Vulnerability Deep Dive
  - Issues by category (Injection, XSS, Auth, etc.)
  - New vs. resolved issues per sprint
  - Average time-to-fix by severity
  - Top 10 most vulnerable files/modules

Dashboard 3: OWASP Top 10 Compliance
  - Heatmap: each OWASP category vs. project
  - Green = compliant, Red = violations present
  - Drill-down to specific rule violations

Dashboard 4: Dependency Risk
  - Total vulnerable dependencies
  - CVSS score distribution
  - Unpatched dependencies over 30/60/90 days
  - Top 10 highest-risk dependencies

Dashboard 5: Secret Detection
  - Gitleaks findings over time
  - Secret types detected (API keys, passwords, tokens)
  - Response time: detection to remediation
```

---

### Phase 6: Custom Rules & Remediation Knowledge Base (Week 6-7)

**Goal:** Tailor the framework to your organization and guide developers.

```
Tasks:
  6.1  Write 20+ custom Semgrep rules for organization-specific patterns
  6.2  Add remediation descriptions to all SonarQube rules
  6.3  Create a secure coding wiki / knowledge base (Markdown or Wiki)
  6.4  Map each rule to OWASP/SANS/CERT reference with explanation
  6.5  Add code examples: vulnerable pattern vs. secure fix
  6.6  Configure issue templates with remediation steps in SonarQube

Deliverable:
  ✓ Custom rules deployed and active
  ✓ Knowledge base published and linked from each finding
```

---

### Phase 7: Performance Optimization & Testing (Week 7-8)

**Goal:** Ensure scans are fast enough to not block developers.

```
Tasks:
  7.1  Benchmark baseline scan times per tool per project size
  7.2  Implement incremental/differential scanning (scan only diffs)
  7.3  Configure parallel tool execution in CI/CD pipelines
  7.4  Tune SonarQube JVM heap settings for available RAM
  7.5  Implement caching for CodeQL databases and dependency scan results
  7.6  Set scan timeout limits (fail fast, don't block indefinitely)
  7.7  Document all optimizations and their measured impact

Deliverable:
  ✓ Full scan completes in under 10 minutes for typical projects
  ✓ Incremental scan (PR diff) completes in under 3 minutes
```

**Performance Targets:**
```
┌─────────────────────┬──────────────┬────────────────────┐
│ Tool                │ Full Scan    │ Incremental Scan   │
├─────────────────────┼──────────────┼────────────────────┤
│ Gitleaks            │ < 30 sec     │ < 5 sec            │
│ Bandit              │ < 60 sec     │ < 15 sec           │
│ ESLint Security     │ < 60 sec     │ < 15 sec           │
│ Semgrep             │ < 2 min      │ < 30 sec           │
│ OWASP Dep-Check     │ < 3 min      │ < 1 min (cached)   │
│ CodeQL              │ < 5 min      │ < 2 min            │
│ SonarQube Scanner   │ < 3 min      │ < 1 min            │
├─────────────────────┼──────────────┼────────────────────┤
│ TOTAL (parallel)    │ < 8 min      │ < 3 min            │
└─────────────────────┴──────────────┴────────────────────┘
```

---

## 8. Security Standards & Rule Mapping

### 8.1 OWASP Top 10 (2021) Coverage

```
A01 - Broken Access Control
  Rules: Missing authorization checks, IDOR patterns, path traversal
  Tools: Semgrep, CodeQL, SonarQube

A02 - Cryptographic Failures
  Rules: Weak algorithms (MD5/SHA1), hardcoded keys, missing TLS
  Tools: Bandit, Semgrep, SonarQube

A03 - Injection
  Rules: SQL injection, command injection, LDAP injection, XSS
  Tools: CodeQL, Semgrep, SonarQube, ESLint

A04 - Insecure Design
  Rules: Missing rate limiting, insecure direct object references
  Tools: Semgrep (custom rules), SonarQube

A05 - Security Misconfiguration
  Rules: Debug mode enabled, default credentials, verbose error messages
  Tools: Semgrep, Bandit, SonarQube

A06 - Vulnerable Components
  Rules: Known CVEs in dependencies, outdated libraries
  Tools: OWASP Dependency-Check

A07 - Identification & Auth Failures
  Rules: Weak passwords, missing MFA, insecure session management
  Tools: Semgrep, CodeQL, SonarQube

A08 - Software & Data Integrity Failures
  Rules: Unsigned packages, missing integrity checks, insecure deserialization
  Tools: Semgrep, CodeQL

A09 - Security Logging & Monitoring Failures
  Rules: Missing log statements for security events, sensitive data in logs
  Tools: Semgrep (custom), SonarQube

A10 - Server-Side Request Forgery (SSRF)
  Rules: Unvalidated URL parameters used in HTTP requests
  Tools: CodeQL, Semgrep, SonarQube
```

### 8.2 SANS/CWE Top 25 Coverage

```
CWE-79  - XSS                    → ESLint, CodeQL, Semgrep
CWE-89  - SQL Injection          → CodeQL, SonarQube
CWE-78  - OS Command Injection   → Bandit (B602), CodeQL
CWE-20  - Improper Input Valid.  → Semgrep, SonarQube
CWE-416 - Use After Free         → CodeQL (C/C++)
CWE-22  - Path Traversal         → Semgrep, CodeQL
CWE-352 - CSRF                   → Semgrep, SonarQube
CWE-434 - Unrestricted Upload    → Semgrep custom rules
CWE-502 - Deserialization        → Bandit (B301), CodeQL
CWE-918 - SSRF                   → CodeQL, Semgrep
```

### 8.3 CERT Secure Coding Standards

```
CERT-C:   EXP34-C, MEM30-C, STR31-C, INT32-C  → CodeQL
CERT-Java: IDS00-J, IDS01-J, OBJ04-J           → SonarQube, CodeQL
CERT-Python: (via Bandit comprehensive tests)   → Bandit
```

---

## 9. Authentication & Access Control Design

### 9.1 Authentication Options (in order of recommendation)

```
Option 1 (Recommended): SAML/SSO Integration
  - Connect SonarQube to existing identity provider
  - Supported providers: Okta, Azure AD, Google Workspace, Keycloak
  - Benefits: Single sign-on, centralized user management, automatic deprovisioning

Option 2: GitHub/GitLab OAuth
  - Users authenticate with their Git credentials
  - Automatic user creation on first login
  - Benefits: No separate credentials to manage

Option 3: LDAP/Active Directory
  - Sync users and groups from corporate directory
  - Benefits: Existing corporate identity infrastructure

Option 4: Local Authentication (minimum baseline)
  - SonarQube-managed usernames and passwords
  - Enforce: minimum 12-char passwords, complexity requirements
  - Enable: 2FA via TOTP (plugin required)
```

### 9.2 Service Account Security

```
CI/CD Pipeline Service Accounts:
  - One service account per pipeline (not shared)
  - Permissions: Scanner Execute, Browse (read-only) specific projects only
  - Token expiry: 90-day rotation
  - Stored in: GitHub Secrets / GitLab CI Variables (encrypted)
  - Never commit tokens to code — Gitleaks will catch this
```

### 9.3 Audit Logging

```
Logged Events:
  - Authentication attempts (success and failure)
  - Permission changes and role assignments
  - Quality gate modifications
  - Rule creation, modification, deletion
  - Issue status changes (mark resolved, false positive)
  - Report exports and data access
  - API token creation and deletion

Log Format: JSON structured logs
Log Retention: 90 days minimum
Log Storage: Separate from application (syslog/ELK/Splunk)
```

---

## 10. Reporting & Visualization Design

### 10.1 Metrics Tracked

```
Security Metrics:
  - Vulnerability Density (issues per 1000 lines of code)
  - Security Rating per project (A through F)
  - Mean Time to Detect (MTTD)
  - Mean Time to Remediate (MTTR)
  - Recurrence Rate (same vulnerability re-introduced)
  - False Positive Rate per tool

Compliance Metrics:
  - OWASP Top 10 categories with open violations
  - CWE categories with open violations
  - Projects passing/failing quality gates
  - Vulnerability age distribution (open > 30/60/90 days)

Dependency Metrics:
  - Total dependencies scanned
  - Vulnerable dependencies by severity
  - Dependencies with no fix available
  - Average dependency freshness (days since last update)
```

### 10.2 Report Types

```
1. Executive Summary Report (monthly)
   Audience: Management, CISO
   Content: Security score trend, top risks, compliance status
   Format: PDF, 2-3 pages

2. Technical Vulnerability Report (weekly)
   Audience: Security team, lead developers
   Content: All open issues, new issues, closed issues, top findings
   Format: PDF + CSV

3. Developer Report (per-project, on-demand)
   Audience: Individual developers
   Content: Issues in their code, remediation steps, links to fixes
   Format: HTML in SonarQube UI

4. Compliance Audit Report (quarterly)
   Audience: Auditors, compliance team
   Content: OWASP/SANS/CERT coverage, open violations, remediation history
   Format: PDF with full issue history
```

---

## 11. CI/CD Integration Design

### 11.1 GitHub Actions Pipeline

```yaml
# .github/workflows/security-scan.yml

name: Security Code Review

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  secret-scan:
    name: Secret Detection (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0}
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dependency-scan:
    name: Dependency Vulnerability Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: ${{ github.repository }}
          path: .
          format: SARIF
          args: --failOnCVSS 7

  sast-python:
    name: Python Security (Bandit)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install bandit
      - run: bandit -r . -f json -o bandit-report.json --severity-level medium
      - uses: actions/upload-artifact@v4
        with:
          name: bandit-report
          path: bandit-report.json

  sast-semgrep:
    name: Semgrep SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/python
            p/javascript
            p/java
            ./semgrep-rules/

  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [python, javascript, java]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3

  sonarqube:
    name: SonarQube Quality Gate
    runs-on: ubuntu-latest
    needs: [secret-scan, dependency-scan, sast-python, sast-semgrep]
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0}
      - uses: SonarSource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
      - uses: SonarSource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### 11.2 Pipeline Flow Summary

```
Parallel Stage 1 (fast, < 1 min):
  ├── Gitleaks secret scan
  └── ESLint security rules

Parallel Stage 2 (medium, < 3 min):
  ├── Bandit (Python)
  ├── Semgrep (all languages)
  └── OWASP Dependency-Check

Sequential Stage 3 (after Stage 2, < 5 min):
  └── CodeQL (depends on build artifacts)

Sequential Stage 4 (final gate, < 2 min):
  └── SonarQube Scanner + Quality Gate check

Result:
  ✓ Pass → PR approved
  ✗ Fail → PR blocked, summary posted as PR comment
```

---

## 12. Performance Optimization Strategy

### 12.1 Scan Speed Optimizations

```
1. Incremental Scanning
   - Only scan files changed in the current PR/commit
   - Semgrep: use --diff-depth flag
   - SonarQube: default behavior with git blame

2. Caching
   - Cache OWASP NVD database (updates daily, not per scan)
   - Cache CodeQL databases between runs
   - Cache pip/npm dependency resolution
   - GitHub Actions: use actions/cache for all tool databases

3. Parallelization
   - Run all Stage 1 and Stage 2 tools simultaneously
   - CodeQL runs language analysis in parallel matrix jobs

4. Resource Tuning (SonarQube server)
   - Set JVM heap: SONAR_WEB_JAVAOPTS=-Xmx2g
   - Set CE JVM: SONAR_CE_JAVAOPTS=-Xmx2g
   - PostgreSQL: shared_buffers=512MB, work_mem=64MB

5. Scan Scope Limits
   - Exclude: test files, generated code, vendor directories
   - Exclude patterns: node_modules/, .git/, build/, dist/, *.min.js
```

### 12.2 Server Hardware Recommendations

```
Minimum (< 5 projects, < 500k LOC):
  CPU: 4 cores
  RAM: 8 GB
  Disk: 50 GB SSD

Recommended (5-20 projects, < 5M LOC):
  CPU: 8 cores
  RAM: 16 GB
  Disk: 200 GB SSD

Large-scale (20+ projects, 5M+ LOC):
  CPU: 16 cores
  RAM: 32 GB
  Disk: 500 GB SSD (or NFS mount)
```

---

## 13. Deliverables Checklist

```
Architecture & Configuration
  [ ] docker-compose.yml — Full stack deployment
  [ ] nginx.conf — Reverse proxy with TLS
  [ ] sonar-project.properties — Template for projects
  [ ] Architecture diagram (this document, Section 6)

Static Analysis Rule Set
  [ ] semgrep-rules/ — Custom YAML rule files (OWASP/SANS/CERT mapped)
  [ ] .bandit.yaml — Bandit configuration
  [ ] .eslintrc.security.json — ESLint security rules
  [ ] sonarqube-rules.xml — Custom SonarQube rules export
  [ ] codeql-config.yml — CodeQL query configuration

CI/CD Integration
  [ ] .github/workflows/security-scan.yml — GitHub Actions
  [ ] .gitlab-ci.yml — GitLab CI equivalent
  [ ] Jenkinsfile — Jenkins pipeline (optional)
  [ ] CI/CD integration guide document

Authentication & RBAC
  [ ] RBAC permission matrix (this document, Section 9)
  [ ] SonarQube LDAP/SAML configuration guide
  [ ] Service account setup guide
  [ ] Access control policy document

Reporting & Visualization
  [ ] Grafana dashboard JSON exports (5 dashboards)
  [ ] Grafana alerting rules configuration
  [ ] Report template configurations
  [ ] Metrics tracking guide

Performance Optimization
  [ ] Benchmark results document
  [ ] SonarQube JVM tuning configuration
  [ ] Caching strategy implementation
  [ ] PostgreSQL performance tuning config

User Training & Documentation
  [ ] Developer quick-start guide
  [ ] Secure coding best practices wiki
  [ ] Remediation guide per vulnerability type
  [ ] Admin operations runbook
  [ ] Tool reference guide
```

---

## 14. Risk Assessment

### 14.1 Technical Risks

```
Risk: False Positives Overwhelming Developers
  Likelihood: High (common with static analysis tools)
  Impact: Medium (alert fatigue, ignored findings)
  Mitigation:
    - Tune rules before go-live, suppress known false positives
    - Set high-confidence rules only in initial rollout
    - Track and review false positive rate monthly
    - Gradually expand rule coverage as trust is built

Risk: Scan Times Too Long — Pipeline Bottleneck
  Likelihood: Medium
  Impact: High (developer frustration, pipeline bypassed)
  Mitigation:
    - Implement incremental scanning from day one
    - Set hard timeout limits (fail after 15 min max)
    - Use parallel job execution
    - Benchmark before go-live and optimize

Risk: SonarQube Server Downtime Blocks Deployments
  Likelihood: Low
  Impact: High (all PRs blocked if SonarQube is down)
  Mitigation:
    - Quality gate configured to "allow on error" for outages
    - Health checks and automatic container restart
    - Database backups (daily automated)
    - Document manual override procedure for emergencies

Risk: Security of the Scanner Itself
  Likelihood: Low
  Impact: Critical (scanner has read access to all source code)
  Mitigation:
    - Run scanner in isolated CI/CD environment
    - Service account tokens with minimal permissions
    - Network isolation — SonarQube not publicly exposed
    - Regular SonarQube version updates
```

### 14.2 Organizational Risks

```
Risk: Developer Resistance / Low Adoption
  Likelihood: Medium
  Impact: High (framework unused, security debt continues)
  Mitigation:
    - Involve developers in rule selection from the start
    - Start with warning mode (report only, no blocking)
    - Gradually enforce blocking for critical severity only
    - Provide clear, actionable remediation guidance
    - Celebrate security improvements publicly

Risk: Incomplete Coverage of Custom Code Patterns
  Likelihood: Medium
  Impact: Medium (organization-specific vulnerabilities missed)
  Mitigation:
    - Schedule quarterly rule review meetings
    - Enable custom rule submission process for developers
    - Review all security incidents for missed rule opportunities
```

---

## 15. Conclusion & Next Steps

### What This Framework Achieves

This framework transforms security from a manual, inconsistent, post-deployment
activity into an **automated, developer-facing, shift-left practice** embedded
directly into the development workflow.

**Key outcomes:**
- Security vulnerabilities caught before code reaches production
- 100% of PRs automatically scanned — no manual initiation required
- Developers receive immediate, actionable guidance — not just alerts
- Security posture tracked over time with measurable metrics
- Compliance with OWASP, SANS, and CERT standards demonstrable via reports
- Zero licensing costs — fully open-source stack

### Immediate Next Steps

```
Week 1:  Set up server, deploy Docker Compose stack (Phase 1)
Week 2:  Install and configure all analysis tools (Phase 2)
Week 3:  Connect to version control, set up CI/CD pipelines (Phase 3)
Week 4:  Configure RBAC and authentication (Phase 4)
Week 5:  Build Grafana dashboards and reports (Phase 5)
Week 6:  Write custom rules and knowledge base (Phase 6)
Week 7:  Performance testing and optimization (Phase 7)
Week 8:  User training, documentation, and go-live
```

### Start Here

To begin implementation immediately, proceed in this order:

1. **Provision a server** (physical, VM, or cloud) meeting minimum hardware specs
2. **Install Docker & Docker Compose** on the server
3. **Deploy the docker-compose.yml** stack (SonarQube + PostgreSQL + Grafana + Nginx)
4. **Verify the platform is accessible** and healthy
5. **Connect your first Git repository** and run a baseline scan

The framework is designed to be **incrementally adoptable** — you can start
with SonarQube alone on day one and add tools progressively without disrupting
existing workflows.

---

*Report prepared for the Secure Code Review Framework research project.*
*All tools referenced are free and open-source. No commercial licenses required.*
*For questions or contributions, refer to each tool's official documentation.*
