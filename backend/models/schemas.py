from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr


# ── Auth ──────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: str
    role: str


# ── User ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "developer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class RoleUpdate(BaseModel):
    role: str


# ── Project ───────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    repo_url: Optional[str] = None
    sonarqube_project_key: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    repo_url: Optional[str] = None
    sonarqube_project_key: Optional[str] = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str]
    repo_url: Optional[str]
    sonarqube_project_key: Optional[str]
    created_by: UUID
    created_at: datetime
    is_active: bool


# ── Scans ─────────────────────────────────────────────────────────────────────

class ScanTrigger(BaseModel):
    scanner: str  # sonarqube/semgrep/bandit/gitleaks/dependency-check
    commit_sha: Optional[str] = None
    branch: Optional[str] = None


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    scanner: str
    status: str
    triggered_by: Optional[UUID]
    commit_sha: Optional[str]
    branch: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    summary: Optional[dict[str, Any]]
    raw_results: Optional[dict[str, Any]]


class IssueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    rule_id: str
    severity: str
    title: str
    description: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    remediation: Optional[str]
    status: str
    created_at: datetime


class IssueUpdate(BaseModel):
    status: str  # open/resolved/false_positive


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportFilter(BaseModel):
    project_id: Optional[UUID] = None
    scanner: Optional[str] = None
    severity: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None


class ScanSummary(BaseModel):
    total_scans: int
    open_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scanners_used: list[str]


class TrendPoint(BaseModel):
    week: str
    critical: int
    high: int
    medium: int
    low: int


class ComplianceItem(BaseModel):
    category: str
    count: int
    risk_level: str


# ── Webhook ───────────────────────────────────────────────────────────────────

class GitHubWebhookPayload(BaseModel):
    ref: str
    after: str
    repository: dict[str, Any]
    commits: list[dict[str, Any]] = []
