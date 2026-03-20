# Performance Optimization Report

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Actual Scan Benchmarks](#2-actual-scan-benchmarks)
3. [Optimization Strategies Implemented](#3-optimization-strategies-implemented)
4. [GitHub Actions Optimization](#4-github-actions-optimization)
5. [Database Performance](#5-database-performance)
6. [Recommendations for Large Codebases](#6-recommendations-for-large-codebases)

---

## 1. Overview

Performance in a security scanning framework is critical. Scans that take too
long slow down developer workflows and cause teams to bypass or ignore security
checks. This report documents actual measured scan times on the
`code-review-framework` codebase and the optimizations applied.

**Test Environment:**
```
Machine:    Dell Latitude 5420
OS:         Ubuntu (native install, no Docker)
CPU:        Intel Core i5 (8 threads)
RAM:        8 GB
Disk:       SSD
Codebase:   code-review-framework (~3,000 lines of Python)
```

---

## 2. Actual Scan Benchmarks

Measured from actual scan runs triggered via the API
(timestamps from `started_at` and `finished_at` in scan_results table):

| Scanner | Start Time | Finish Time | Duration | Issues Found |
|---|---|---|---|---|
| Gitleaks | 19:26:52 | 19:26:57 | **5 seconds** | 1 critical |
| Bandit | 18:42:43 | 18:42:45 | **2 seconds** | 9 issues |
| Semgrep | 19:40:20 | 19:40:39 | **19 seconds** | 29 issues |
| Dependency-Check (cached NVD) | 22:53:40 | 22:53:46 | **6 seconds** | 0 |
| Dependency-Check (fresh NVD) | First run | — | **~172 minutes** | — |

**Key observation:** Dependency-Check first run is very slow (NVD database
download of 338,684 CVE records). Subsequent runs with cached database take
only 6 seconds.

### Summary

```
Fastest scanner:   Bandit          — 2 seconds
Slowest scanner:   Semgrep         — 19 seconds
All scanners (sequential): ~32 seconds total
All scanners (parallel):   ~19 seconds (limited by slowest)
```

---

## 3. Optimization Strategies Implemented

### 3.1 Background Task Processing (Non-Blocking)
**What:** Scans run as FastAPI background tasks — the API returns immediately
with a `pending` scan record, and the actual scanning happens asynchronously.

**Why:** Without this, the API call would hang for 19+ seconds waiting for
Semgrep to complete. Developers get instant feedback that the scan is queued.

**Implementation:** `background_tasks.add_task(service.run_scan, ...)`

**Impact:** API response time: **< 100ms** regardless of scan duration.

---

### 3.2 Async Scanner Architecture
**What:** All scanners use `asyncio.create_subprocess_exec()` instead of
blocking `subprocess.run()`.

**Why:** Allows multiple scans to run concurrently without blocking the
FastAPI event loop.

**Implementation:** All scanner `scan()` methods are `async def`.

**Impact:** Multiple projects can be scanned simultaneously without queuing.

---

### 3.3 NVD Database Caching (Dependency-Check)
**What:** OWASP Dependency-Check downloads the NVD database once and caches
it locally at `/opt/dependency-check/data/`.

**Why:** First download takes ~172 minutes (338k records). Without caching,
every scan would take this long.

**Impact:**
- First run: ~172 minutes (one-time only)
- All subsequent runs: **6 seconds** (cached)
- Cache updates: Daily incremental update (fast)

---

### 3.4 Async File I/O
**What:** Scanner report files are read using `aiofiles` (async file I/O)
instead of blocking `open()`.

**Why:** Prevents blocking the event loop when reading large JSON reports.

**Implementation:** `async with aiofiles.open(report_file) as f:`

**Impact:** Other requests are not blocked while reading scan output files.

---

### 3.5 Scan Timeout Limits
**What:** All subprocess scans have timeout limits.

| Scanner | Timeout |
|---|---|
| Gitleaks | 5 minutes |
| Dependency-Check | 10 minutes |

**Why:** Prevents a hung scan from blocking background workers indefinitely.

**Implementation:** `asyncio.wait_for(proc.communicate(), timeout=300)`

---

### 3.6 Repo Cleanup After Scan
**What:** Cloned repositories are deleted from `/tmp/scans/` after each scan completes.

**Why:** Prevents disk space accumulation on the server.

**Implementation:** `shutil.rmtree(cloned_path, ignore_errors=True)` in finally block.

---

## 4. GitHub Actions Optimization

### 4.1 Parallel Job Execution
All 5 CI jobs run in parallel on GitHub's cloud:

```
Time 0s ──────────────────────────────────────────► Time ~5min
  │
  ├── Semgrep (2-3 min)          ████████████
  ├── Bandit (1-2 min)           █████
  ├── Gitleaks (< 1 min)         ██
  ├── Dependency-Check (2-3 min) ████████████
  └── CodeQL Python (3-5 min)    ████████████████████
      CodeQL JavaScript (3-5 min) ████████████████████
  │
  └── notify-framework (after all above) ─ 10 seconds
```

**Total wall time:** ~5 minutes (limited by slowest job — CodeQL)
**Without parallelism:** ~15 minutes (sequential)
**Savings:** ~10 minutes per CI run

### 4.2 Artifact Retention
Build artifacts (bandit-report.json, dependency-check-report) are retained
for 30 days then auto-deleted. This keeps GitHub Actions storage usage low.

### 4.3 Continue on Error
Semgrep uses `continue-on-error: true` for the SARIF upload step so that
even if results upload fails, the rest of the pipeline continues.

---

## 5. Database Performance

### 5.1 Database Indexes
The following indexes are created for fast query performance:

```sql
-- Fast lookup of issues by scan
ix_issues_scan_id ON issues(scan_id)

-- Fast lookup of scans by project
ix_scan_results_project_id ON scan_results(project_id)

-- Fast lookup of comments by issue
ix_issue_comments_issue_id ON issue_comments(issue_id)

-- Fast user lookup by username
ix_users_username ON users(username)

-- Fast project lookup by name
ix_projects_name ON projects(name)
```

### 5.2 Query Optimization
- Grafana queries use `public.` schema prefix for explicit table resolution
- All list endpoints have `skip` and `limit` parameters for pagination
- Issues queries filter by `status = 'open'` to exclude resolved/false positive

### 5.3 JSONB for Flexible Data
`summary` and `raw_results` columns use JSONB type (binary JSON) which is:
- Faster to query than text JSON
- Supports indexing on JSON fields if needed
- Flexible — different scanners return different summary structures

---

## 6. Recommendations for Large Codebases

If using this framework on large codebases (100k+ lines of code):

### 6.1 Increase Scan Timeouts
For very large repos, increase timeout limits in scanner files:
```python
# In each scanner file
await asyncio.wait_for(proc.communicate(), timeout=900)  # 15 minutes
```

### 6.2 Use Incremental Scanning
Configure Semgrep to only scan changed files:
```bash
semgrep --config p/owasp-top-ten \
        --diff-depth 2 \
        $(git diff --name-only HEAD~1)
```

### 6.3 NVD API Key for Dependency-Check
Register for a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

Add to dependency-check command:
```bash
dependency-check --nvdApiKey YOUR_KEY_HERE --scan .
```

**Impact:** Update speed increases from 6 requests/min to 30 requests/min.

### 6.4 Hardware Recommendations

| Codebase Size | RAM | CPU | Disk |
|---|---|---|---|
| < 50k LOC | 8 GB | 4 cores | 50 GB SSD |
| 50k-500k LOC | 16 GB | 8 cores | 200 GB SSD |
| 500k+ LOC | 32 GB | 16 cores | 500 GB SSD |

### 6.5 PostgreSQL Tuning
For high scan volume, add to `postgresql.conf`:
```
shared_buffers = 256MB
work_mem = 64MB
max_connections = 100
```

---

*Document Version 1.0 — Secure Code Review Framework*
