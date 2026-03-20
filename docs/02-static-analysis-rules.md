# Static Analysis Rule Set

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [OWASP Top 10 Coverage](#2-owasp-top-10-coverage)
3. [SANS CWE Top 25 Coverage](#3-sans-cwe-top-25-coverage)
4. [CERT Secure Coding Coverage](#4-cert-secure-coding-coverage)
5. [Scanner Rule Configuration](#5-scanner-rule-configuration)
6. [Custom Semgrep Rules](#6-custom-semgrep-rules)
7. [Rule to Scanner Mapping](#7-rule-to-scanner-mapping)
8. [Severity Classification](#8-severity-classification)

---

## 1. Overview

The framework applies security rules from three industry standards:

| Standard | Purpose | Coverage |
|---|---|---|
| OWASP Top 10 (2021) | Web application security risks | All 10 categories |
| SANS CWE Top 25 | Most dangerous software weaknesses | 10+ CWEs covered |
| CERT Secure Coding | Language-specific secure coding | Python, Java |

Every issue detected by any scanner is automatically mapped to:
- **CWE ID** — Common Weakness Enumeration identifier
- **OWASP Category** — OWASP Top 10 category code
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Remediation** — Step-by-step fix guidance

---

## 2. OWASP Top 10 Coverage

### A01:2021 — Broken Access Control
**What it detects:** Missing authorization checks, insecure direct object references, path traversal attacks.

**Scanners:** Semgrep, CodeQL, SonarQube

**Example rules active:**
- Missing authentication on sensitive endpoints
- Path traversal via user-supplied file paths
- IDOR — accessing resources without ownership check

---

### A02:2021 — Cryptographic Failures
**What it detects:** Weak encryption algorithms, hardcoded cryptographic keys, missing TLS, sensitive data exposure.

**Scanners:** Bandit, Semgrep, SonarQube

**Bandit rules active:**
- `B303` — Use of MD5 or SHA1 (weak hash)
- `B304` — Use of insecure cipher modes
- `B501` — Request with certificate validation disabled
- `B502` — SSL with bad version
- `B506` — Use of unsafe YAML load

**Example Semgrep rules:**
- Hardcoded passwords in source code
- Use of `hashlib.md5()` without `usedforsecurity=False`

---

### A03:2021 — Injection
**What it detects:** SQL injection, command injection, LDAP injection, XSS.

**Scanners:** CodeQL, Semgrep, SonarQube, Bandit

**Bandit rules active:**
- `B601` — Paramiko calls with policy disabled
- `B602` — `subprocess` call with shell=True (command injection)
- `B603` — `subprocess` without shell=True
- `B604` — Function call with shell=True
- `B605` — `os.system` call (command injection)
- `B606` — `os.popen` call
- `B608` — Possible SQL injection via string formatting

---

### A04:2021 — Insecure Design
**What it detects:** Missing rate limiting, insecure direct object references, design-level security flaws.

**Scanners:** Semgrep (custom rules), SonarQube

---

### A05:2021 — Security Misconfiguration
**What it detects:** Debug mode enabled, default credentials, overly permissive CORS, verbose error messages.

**Scanners:** Semgrep, Bandit, SonarQube

**Bandit rules active:**
- `B104` — Binding to all interfaces (0.0.0.0)
- `B105` — Hardcoded password string
- `B106` — Hardcoded password as function argument
- `B107` — Hardcoded password as default argument

---

### A06:2021 — Vulnerable and Outdated Components
**What it detects:** Known CVEs in project dependencies, outdated libraries.

**Scanners:** OWASP Dependency-Check, GitHub Actions CodeQL

**How it works:**
- OWASP Dependency-Check downloads the full NVD database (338k+ CVE records)
- Scans `requirements.txt`, `package.json`, `pom.xml`
- Matches installed versions against known vulnerable versions
- Fails build if CVSS score ≥ 7.0 (HIGH)

**CWE Mapping:** CWE-1035 (Using Components with Known Vulnerabilities)
**OWASP Mapping:** A06:2021

---

### A07:2021 — Identification and Authentication Failures
**What it detects:** Weak passwords, insecure session management, hardcoded credentials, exposed secrets.

**Scanners:** Gitleaks, Bandit, Semgrep

**Gitleaks — Secret types detected:**
- Generic API keys
- AWS access keys and secret keys
- GitHub tokens and personal access tokens
- Google API keys
- Stripe API keys
- Private SSH keys
- Database connection strings with passwords
- JWT tokens
- Generic passwords in config files

**Bandit rules active:**
- `B105` — Hardcoded password string
- `B106` — Hardcoded password as function argument
- `B107` — Hardcoded password as default argument
- `B108` — Hardcoded tmp directory

**CWE Mapping:** CWE-798 (Use of Hard-coded Credentials)

---

### A08:2021 — Software and Data Integrity Failures
**What it detects:** Insecure deserialization, missing integrity checks, unsigned packages.

**Scanners:** Bandit, CodeQL, Semgrep

**Bandit rules active:**
- `B301` — Use of `pickle` (insecure deserialization)
- `B302` — Use of `marshal` (insecure deserialization)
- `B403` — Import of `pickle` module
- `B506` — Use of unsafe `yaml.load()` instead of `yaml.safe_load()`

---

### A09:2021 — Security Logging and Monitoring Failures
**What it detects:** Missing log statements for security events, sensitive data logged in plaintext.

**Scanners:** Semgrep (custom rules), SonarQube

---

### A10:2021 — Server-Side Request Forgery (SSRF)
**What it detects:** Unvalidated URL parameters used in HTTP requests, requests to internal services.

**Scanners:** CodeQL, Semgrep, SonarQube

---

## 3. SANS CWE Top 25 Coverage

| CWE | Name | Scanner | Rule/Method |
|---|---|---|---|
| CWE-79 | Cross-site Scripting (XSS) | Semgrep, CodeQL | Template injection, unescaped output |
| CWE-89 | SQL Injection | CodeQL, Bandit (B608) | String formatting in SQL queries |
| CWE-78 | OS Command Injection | Bandit (B602, B605) | subprocess shell=True, os.system() |
| CWE-20 | Improper Input Validation | Semgrep, SonarQube | Missing input sanitization |
| CWE-22 | Path Traversal | Semgrep, CodeQL | User input in file paths |
| CWE-352 | CSRF | Semgrep, SonarQube | Missing CSRF tokens |
| CWE-434 | Unrestricted File Upload | Semgrep custom rules | Missing file type validation |
| CWE-502 | Deserialization of Untrusted Data | Bandit (B301, B302) | pickle, marshal usage |
| CWE-798 | Hardcoded Credentials | Gitleaks, Bandit | Secret patterns in code |
| CWE-918 | SSRF | CodeQL, Semgrep | Unvalidated URLs in HTTP calls |
| CWE-1035 | Vulnerable Components | OWASP Dependency-Check | CVE database matching |

---

## 4. CERT Secure Coding Coverage

### Python (via Bandit)
| CERT Rule | Description | Bandit Test |
|---|---|---|
| MSC62-PY | Do not use weak cryptographic algorithms | B303, B304 |
| MSC61-PY | Do not use the `exec` statement | B102 |
| IDS31-PY | Do not use the `eval()` function | B307 |
| IDS33-PY | Do not use the `input()` function in Python 2 | B322 |

### Java (via SonarQube + CodeQL)
| CERT Rule | Description | Tool |
|---|---|---|
| IDS00-J | Prevent SQL injection | SonarQube, CodeQL |
| IDS01-J | Normalize strings before validation | SonarQube |
| OBJ04-J | Do not allow partially initialized objects | CodeQL |

---

## 5. Scanner Rule Configuration

### 5.1 Semgrep Configuration
Semgrep runs with the following rule packs in GitHub Actions:

```yaml
semgrep \
  --config p/owasp-top-ten \
  --config p/python \
  --config p/javascript \
  --config p/java \
  --sarif \
  --output semgrep-results.sarif \
  --severity ERROR \
  --severity WARNING
```

**Rule packs active:**
- `p/owasp-top-ten` — OWASP Top 10 2021 rules
- `p/python` — Python-specific security rules
- `p/javascript` — JavaScript/TypeScript security rules
- `p/java` — Java security rules

**Custom rules directory:** `semgrep-rules/`

---

### 5.2 Bandit Configuration
Bandit scans all Python files with these settings:

```bash
bandit -r . \
  -f json \
  -o bandit-report.json \
  -ll \
  --exclude ./.git,./tests/vulnerable_samples
```

**Flags:**
- `-r` — recursive scan
- `-ll` — report medium and high severity only
- `--exclude` — skip test vulnerable samples and git directory

**Severity threshold:** MEDIUM and above
**Confidence threshold:** LOW and above

---

### 5.3 Gitleaks Configuration
```bash
gitleaks git . \
  --report-format json \
  --report-path gitleaks-report.json \
  --exit-code 0
```

Scans the full git history for exposed secrets.
Custom rules can be added via `.gitleaks.toml`.

---

### 5.4 OWASP Dependency-Check Configuration
```bash
dependency-check \
  --scan . \
  --format JSON \
  --out /tmp/dc-report \
  --disableAssembly \
  --failOnCVSS 7
```

**Flags:**
- `--disableAssembly` — skip .NET assembly analysis
- `--failOnCVSS 7` — fail build if any CVE score ≥ 7.0 (HIGH)

**NVD Database:** Downloaded locally to `/opt/dependency-check/data/`
**Update frequency:** Daily on first scan of the day

---

## 6. Custom Semgrep Rules

Custom rules are stored in `semgrep-rules/` directory.
These target organization-specific patterns beyond the default rule packs.

**Location:** `semgrep-rules/`

**How to add a new custom rule:**

Create a YAML file in `semgrep-rules/`:

```yaml
rules:
  - id: no-hardcoded-api-url
    patterns:
      - pattern: |
          $URL = "http://api.internal-company.com/..."
    message: |
      Hardcoded internal API URL found. Use environment
      variables instead: os.environ.get('API_URL')
    languages: [python]
    severity: WARNING
    metadata:
      owasp: A05:2021
      cwe: CWE-547
```

---

## 7. Rule to Scanner Mapping

| Vulnerability Type | Semgrep | Bandit | Gitleaks | OWASP DC | SonarQube | CodeQL |
|---|---|---|---|---|---|---|
| SQL Injection | Yes | B608 | — | — | Yes | Yes |
| Command Injection | Yes | B602, B605 | — | — | Yes | Yes |
| XSS | Yes | — | — | — | Yes | Yes |
| Hardcoded Secrets | Yes | B105-107 | Yes | — | Yes | — |
| Weak Cryptography | Yes | B303, B304 | — | — | Yes | — |
| Insecure Deserialization | Yes | B301, B302 | — | — | Yes | Yes |
| Path Traversal | Yes | — | — | — | Yes | Yes |
| SSRF | Yes | — | — | — | Yes | Yes |
| Vulnerable Dependencies | — | — | — | Yes | — | — |
| Secrets in Git History | — | — | Yes | — | — | — |
| CSRF | Yes | — | — | — | Yes | — |
| Insecure File Upload | Yes | — | — | — | — | — |

---

## 8. Severity Classification

### Severity Levels

| Level | CVSS Score | Description | Action Required |
|---|---|---|---|
| CRITICAL | 9.0 - 10.0 | Immediately exploitable, severe impact | Fix before merge — PR blocked |
| HIGH | 7.0 - 8.9 | Significant risk, likely exploitable | Fix within 24 hours |
| MEDIUM | 4.0 - 6.9 | Moderate risk, requires specific conditions | Fix within sprint |
| LOW | 0.1 - 3.9 | Minor risk, limited impact | Fix when convenient |
| INFO | 0.0 | Informational, best practice | Review and decide |

### How Severity is Determined

**Semgrep:** Based on rule severity (ERROR → HIGH, WARNING → MEDIUM)

**Bandit:** Based on `issue_severity` field:
- HIGH → HIGH
- MEDIUM → MEDIUM
- LOW → LOW

**Gitleaks:** All secrets detected → CRITICAL (any exposed credential is critical)

**OWASP Dependency-Check:** Based on CVSS score:
```
CVSS ≥ 9.0  → CRITICAL
CVSS ≥ 7.0  → HIGH
CVSS ≥ 4.0  → MEDIUM
CVSS < 4.0  → LOW
```

**SonarQube:** Uses its own severity system (BLOCKER/CRITICAL/MAJOR/MINOR/INFO)
mapped to framework severity on import.

---

*Document Version 1.0 — Secure Code Review Framework*
*Rules aligned with OWASP Top 10 2021, SANS CWE Top 25, and CERT Secure Coding Standards.*
