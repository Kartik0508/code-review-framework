import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from backend.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="developer")  # admin/reviewer/developer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    projects = relationship("Project", back_populates="creator", foreign_keys="[Project.created_by]")
    scan_results = relationship("ScanResult", back_populates="triggerer", foreign_keys="[ScanResult.triggered_by]")
    audit_logs = relationship("AuditLog", back_populates="user")


class Project(Base):
    __tablename__ = "projects"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    repo_url = Column(String(500), nullable=True)
    sonarqube_project_key = Column(String(200), nullable=True)
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    creator = relationship("User", back_populates="projects", foreign_keys=[created_by])
    scan_results = relationship("ScanResult", back_populates="project", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PG_UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True)
    scanner = Column(String(100), nullable=False)  # sonarqube/semgrep/bandit/gitleaks/dependency-check
    status = Column(String(50), nullable=False, default="pending")  # pending/running/completed/failed
    triggered_by = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    commit_sha = Column(String(100), nullable=True)
    branch = Column(String(200), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(JSONB, nullable=True)   # {total, critical, high, medium, low, info}
    raw_results = Column(JSONB, nullable=True)

    project = relationship("Project", back_populates="scan_results")
    triggerer = relationship("User", back_populates="scan_results", foreign_keys=[triggered_by])
    issues = relationship("Issue", back_populates="scan", cascade="all, delete-orphan")


class Issue(Base):
    __tablename__ = "issues"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scan_results.id"), nullable=False, index=True)
    rule_id = Column(String(200), nullable=False)
    severity = Column(String(50), nullable=False)  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(1000), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    cwe_id = Column(String(50), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="open")  # open/resolved/false_positive
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanResult", back_populates="issues")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(200), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(200), nullable=True)
    details = Column(JSONB, nullable=True)
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="audit_logs")
